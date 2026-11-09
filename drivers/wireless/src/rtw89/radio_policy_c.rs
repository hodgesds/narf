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
//!   14 (CCK-only) never does. Its binding covers the base record
//!   digest/signer, which must also sign it.
//! * 6GHz `N5CC` v1 (`rtw89/rtw8852c-chan-v1-6g-ch<primary>-bw<width>-regd<NN>-
//!   <vlp|lpi|sp>-<mac>.bin`): one typed 6GHz profile (20/40/80/160MHz)
//!   under one `radio_power_c::SixGhzPower` (the country's rtw89 6GHz regd
//!   and `reg_6ghz_power`), bytes 70/71 = power/regd. The envelope check
//!   additionally requires every rule over the span to admit a client of
//!   that power type (cfg80211 `cfg80211_6ghz_power_type_valid`:
//!   `NO_6GHZ_VLP_CLIENT`/`NO_6GHZ_AFC_CLIENT`), and accepts INDOOR_ONLY
//!   only with the trusted DEPLOYMENT_INDOOR assertion.
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
use super::radio_policy::{Lifecycle, Program};
use super::{
    factory::Factory,
    radio_assets::Assets,
    radio_power_c::{Plan, SixGhzPower},
};
use alloc::format;
use narf_capabilities::{Cap, CapError, CapOp, Read};
use narf_firmware::{FirmwareBlob, FirmwareError};
use narf_wireless::reg::RegulatoryDomain;
const LENGTH: usize = 128;
/// Profile byte 57: the B base flags with no optional program bit.
const BASE_FLAGS: u8 = 3;
/// Optional operating programs a C base record may enable (byte 57, the
/// B `radio_policy::Program` bit layout and dependencies). Only programs
/// whose whole C path exists are admitted; the others stay refused.
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
/// Extend a C identity by one enabled program (domain-separated from B's
/// `Program::extend`; the station H2C/TXWD programs are the common AX code
/// the B fingerprints measure, sent through the C v1 TXWD path).
fn extend(program: Program, identity: [u8; 32]) -> [u8; 32] {
    let mut hash = narf_crypto::sha256::Sha256::new();
    match program {
        Program::Wmm => {
            hash.update(
                b"NARF RTL8852C WMM BE/TID0 legacy12 optional operating recipe v1;txwd_body_v1",
            );
            hash.update(&identity);
            hash.update(&super::station_control::wmm_fingerprint());
        }
        Program::QosAll => {
            hash.update(
                b"NARF RTL8852C WMM all-AC TID0..7 optional operating recipe v1;txwd_body_v1;ach0..3_v1",
            );
            hash.update(&identity);
            hash.update(&super::station_control::qos_all_fingerprint());
        }
        Program::FirmwareRa => {
            hash.update(
                b"NARF RTL8852C firmware RA legacy optional operating recipe v1;txwd_info0_v1",
            );
            hash.update(&identity);
            hash.update(&super::station_control::firmware_ra_fingerprint());
        }
        Program::Ht => {
            hash.update(
                b"NARF RTL8852C HT20 optional operating recipe v1;rx_desc_v1;bacam_v0_ext8",
            );
            hash.update(&identity);
            hash.update(&super::station_control::ht_fingerprint());
        }
        Program::He => {
            hash.update(
                b"NARF RTL8852C HE20 optional operating recipe v1;txwd_info0_v1 DATA_ER;rx_desc_v1",
            );
            hash.update(&identity);
            hash.update(&super::station_control::he_fingerprint());
        }
        Program::Ampdu => {
            hash.update(b"NARF RTL8852C originator BA TX A-MPDU optional operating recipe v1;txwd_body3/info1/info2 v1 agg;h2c_ampdu_cmac_tbl NULL on 8852C");
            hash.update(&identity);
            hash.update(&super::station_control::ampdu_fingerprint());
        }
    }
    hash.finalize()
}

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
    } else if profile.band() == Band::Ghz6 {
        b"NARF RTL8852C 6GHz full RF awake WLAN-only v1;TX path RF_B (rtw8852c_ctrl_tx_path_tmac),RX-AB;no CCK;no hardwarecrypto;HE-only;retuned across band from Ready ch1 program"
    } else {
        b"NARF RTL8852C noninitial full RF 2.4GHz awake WLAN-only v1;TX-A,RX-AB;no hardwarecrypto;retuned from Ready ch1 program"
    }
}
/// Width in MHz as the one byte the C record identity and the N5CC
/// channel image carry it. 320MHz has no `u8` MHz encoding, so it is
/// the sentinel 0: no station width is 0MHz, so the byte still
/// distinguishes all five widths unambiguously.
fn width_mhz(width: Width) -> u8 {
    match width {
        Width::Mhz20 => 20,
        Width::Mhz40 => 40,
        Width::Mhz80 => 80,
        Width::Mhz160 => 160,
        Width::Mhz320 => 0,
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
/// Typed 6GHz profiles a 6GHz `N5CC` record may admit (with a power
/// context): every 6GHz 20/40/80/160/320MHz block (`operating_channel_c`).
pub(super) fn admissible_6ghz(profile: Profile) -> bool {
    profile.band() == Band::Ghz6
}
/// Every typed 6GHz profile, in a fixed order.
pub(super) fn noninitial_6ghz() -> alloc::vec::Vec<Profile> {
    let mut out = alloc::vec::Vec::new();
    for primary in (1..=233).filter(|&p| super::operating_channel_c::is_6ghz_primary(p)) {
        out.extend(Profile::new20(Band::Ghz6, primary));
        for width in [Width::Mhz40, Width::Mhz80, Width::Mhz160, Width::Mhz320] {
            out.extend(Profile::new_wide(Band::Ghz6, primary, width));
        }
    }
    out
}
/// The power types a 6GHz record may be measured for (an unset AP type is
/// refused by cfg80211 before a 6GHz BSS is usable).
pub(super) const POWER_TYPES_6GHZ: [narf_wireless::reg::PowerType6Ghz; 3] = [
    narf_wireless::reg::PowerType6Ghz::Vlp,
    narf_wireless::reg::PowerType6Ghz::Lpi,
    narf_wireless::reg::PowerType6Ghz::Sp,
];
/// `reg_6ghz_power` back to the cfg80211 client power type it admits.
pub(super) fn client_type(six: SixGhzPower) -> narf_wireless::reg::PowerType6Ghz {
    use narf_wireless::reg::PowerType6Ghz;
    match six.power() {
        1 => PowerType6Ghz::Lpi,
        2 => PowerType6Ghz::Sp,
        _ => PowerType6Ghz::Vlp,
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
    /// 6GHz only: the power context the record identity binds.
    six: Option<SixGhzPower>,
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
        let six = power.six_ghz().map(|(p, _)| p);
        let admitted = if six.is_some() {
            admissible_6ghz(profile)
        } else {
            admissible(profile)
        };
        if !admitted || !phycap.is_c() {
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
        if six.is_some() {
            // A 6GHz record binds the HE-only 6GHz station recipe: HE
            // Capabilities + HE 6GHz Band Capabilities, no HT/VHT element
            // (mac80211 `ieee80211_add_link_elems` on 6GHz).
            h.update(SIX_GHZ_STATION);
        } else {
            // A 40/80MHz record also binds the shared wide station
            // capability its channel lets the station offer
            // (`station_control::wide_phy`).
            if matches!(profile.width(), Width::Mhz40 | Width::Mhz80) {
                h.update(&super::station_control::wide_fingerprint());
            }
            // A 160MHz record binds the C 160MHz station capability and RA
            // recipe (`station_control::wide160_fingerprint`) instead.
            if profile.width() == Width::Mhz160 {
                h.update(&super::station_control::wide160_fingerprint());
            }
        }
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
            six,
        })
    }
    pub(super) fn six_ghz(&self) -> Option<SixGhzPower> {
        self.six
    }
    pub fn identity(&self) -> [u8; 32] {
        self.identity
    }
    /// Extend the identity by every C program enabled in `flags`, in the
    /// fixed `PROGRAMS` order (as B's `Board::with_programs`).
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

/// The 6GHz station recipe a 6GHz record identity binds.
const SIX_GHZ_STATION: &[u8] = b"NARF RTL8852C HE-only 6GHz station v1;HE cap + HE 6GHz band cap (ieee80211_he_6ghz_capa);no HT/VHT;RA HE-only (rtw89_phy_ra_sta_update, RTW89_BAND_6G)";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Envelope {
    span: (u32, u32),
    /// 6GHz only: the client power type every overlapping rule must admit.
    client: Option<narf_wireless::reg::PowerType6Ghz>,
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
fn envelope(bytes: &[u8], profile: Profile, six: Option<SixGhzPower>) -> Result<Envelope, Error> {
    envelope_at(
        bytes,
        profile.occupied(),
        profile.width().mhz(),
        six.map(client_type),
    )
}
/// The signed antenna/ceiling/peaks (bytes 58..68) over an occupied span of
/// `width` MHz; shared with the RTL8851B family (`radio_policy_51`).
pub(super) fn envelope_at(
    bytes: &[u8],
    span: (u32, u32),
    width: u32,
    client: Option<narf_wireless::reg::PowerType6Ghz>,
) -> Result<Envelope, Error> {
    let signed = |at: usize| i16::from_le_bytes([bytes[at], bytes[at + 1]]);
    let e = Envelope {
        span,
        client,
        width,
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
pub(super) fn loader() -> Result<Cap<narf_firmware::FirmwareRegistry, Read>, Error> {
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
    if profile.band() == Band::Ghz6 {
        b"RTL8852C 6GHz noninitial full operating program v1; __rtw89_set_channel with btc switch band and rtw8852c_tssi_scan on a band change, then rtw8852c_rfk_channel on a Ready owner; actual primary/width 6GHz regd/reg_6ghz_power limits and RU limits (TPE only lowers them), no CCK; worst-case peaks/antenna cover all calibration emissions on this profile under the current host rule and client power type over the whole occupied span"
    } else if profile.band() == Band::Ghz5 {
        b"RTL8852C 5GHz noninitial full operating program v1; __rtw89_set_channel with btc switch band and rtw8852c_tssi_scan on a band change, then rtw8852c_rfk_channel on a Ready owner; actual primary/width WW0 limits and RU limits, no CCK; worst-case peaks/antenna cover all calibration emissions on this profile under the current host rule over the whole occupied span"
    } else {
        b"RTL8852C 2.4GHz noninitial full operating program v1; __rtw89_set_channel then rtw8852c_rfk_channel on a Ready owner; same band, no band-change TSSI scan; actual primary/width WW0 CCK/OFDM limits, SCO CCK and TX shape; worst-case peaks/antenna cover all calibration emissions on this profile under the current host rule over the whole occupied span"
    }
}
fn binding(base: &Qualification, board: Board) -> Result<[u8; 32], Error> {
    let profile = board.profile;
    let admitted = match board.six {
        Some(_) => admissible_6ghz(profile),
        None => admissible(profile),
    };
    if profile == Profile::INITIAL
        || !admitted
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
    if let Some(six) = board.six {
        hash.update(&[six.power(), six.regd()]);
    }
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
/// Firmware name of the 6GHz `N5CC` record for `profile` under `six`.
pub(super) fn channel_name_6ghz(
    profile: Profile,
    six: SixGhzPower,
    mac: [u8; 6],
) -> alloc::string::String {
    let m = mac;
    format!(
        "rtw89/rtw8852c-chan-v1-6g-ch{:03}-bw{}-regd{:02}-{}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}.bin",
        profile.primary(),
        width_mhz(profile.width()),
        six.regd(),
        match six.power() {
            1 => "lpi",
            2 => "sp",
            _ => "vlp",
        },
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
            || bytes[70..72] != board.six.map_or([0, 0], |s| [s.power(), s.regd()])
            || bytes[72..] != [0; 56]
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
            envelope: envelope(bytes, p, board.six)?,
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
    /// Byte 57 of the base record: base flags plus enabled `PROGRAMS`.
    flags: u8,
    channels: alloc::vec::Vec<Channel>,
    /// Profile (and 6GHz power context) whose envelope gates every
    /// publication.
    active: narf_lib::sync::IrqSafeSpinLock<(Profile, Option<SixGhzPower>)>,
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
        let envelope = envelope(bytes, Profile::INITIAL, None)?;
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
            active: narf_lib::sync::IrqSafeSpinLock::new((Profile::INITIAL, None)),
            #[cfg(any(test, feature = "kernel-test"))]
            model_domain: None,
        })
    }
    /// `board` is the program-free identity [`Board::new`] rebinds; the
    /// record measured it extended by its own enabled programs.
    pub fn matches(&self, board: Board) -> bool {
        self.board == board.with_programs(self.flags)
    }
    /// Whether the base record enables `program` (current authority only).
    pub(super) fn allows(&self, program: Program) -> Result<bool, Error> {
        self.current()?;
        Ok(self.flags & program.bit() != 0)
    }
    /// Load the optional `N5CC` record for `board.profile()` (a noninitial
    /// identity from [`Board::new`]). Absent: `Ok(false)`, unadmitted.
    pub(super) fn load_channel(&mut self, board: Board) -> Result<bool, Error> {
        if board.six.is_some() {
            return Err(Error::Identity);
        }
        binding(self, board)?;
        let name = channel_name(board.profile, self.board.mac);
        self.load_named(&name, board)
    }
    /// Whether a 6GHz `N5CC` record for `profile` under `six` is
    /// provisioned (named lookup only; nothing is decoded or installed).
    pub(super) fn has_channel_6ghz(
        &self,
        profile: Profile,
        six: SixGhzPower,
    ) -> Result<bool, Error> {
        let name = channel_name_6ghz(profile, six, self.board.mac);
        match narf_firmware::open(&name, &loader()?) {
            Ok(_) => Ok(true),
            Err(FirmwareError::NotFound) => Ok(false),
            Err(error) => Err(Error::Firmware(error)),
        }
    }
    /// Load the 6GHz `N5CC` record for a 6GHz `board` (built from a
    /// `radio_power_c` 6GHz plan). Absent: `Ok(false)`, unadmitted.
    pub(super) fn load_channel_6ghz(&mut self, board: Board) -> Result<bool, Error> {
        let six = board.six.ok_or(Error::Identity)?;
        binding(self, board)?;
        let name = channel_name_6ghz(board.profile, six, self.board.mac);
        self.load_named(&name, board)
    }
    fn load_named(&mut self, name: &str, board: Board) -> Result<bool, Error> {
        let cap = match narf_firmware::open(name, &loader()?) {
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
        let key = (record.board.profile, record.board.six);
        self.channels
            .retain(|c| (c.board.profile, c.board.six) != key);
        self.channels.push(record);
    }
    fn channel(&self, profile: Profile, six: Option<SixGhzPower>) -> Option<&Channel> {
        self.channels
            .iter()
            .find(|c| c.board.profile == profile && c.board.six == six)
    }
    /// The loaded record for `profile` was measured for exactly `board`.
    pub(super) fn channel_matches(&self, board: Board) -> bool {
        if board.profile == Profile::INITIAL {
            return self.matches(board);
        }
        self.channel(board.profile, board.six)
            .is_some_and(|record| record.board == board)
    }
    /// The 6GHz power contexts with a loaded record for `profile`.
    pub(super) fn six_ghz_contexts(&self, profile: Profile) -> alloc::vec::Vec<SixGhzPower> {
        self.channels
            .iter()
            .filter(|c| c.board.profile == profile)
            .filter_map(|c| c.board.six)
            .collect()
    }
    /// Current signed admission of `profile`: a record exists, is bound to
    /// this base, and the current host rule over its span passes.
    pub(super) fn channel_allowed(&self, profile: Profile) -> Result<bool, Error> {
        self.channel_allowed_in(profile, None)
    }
    /// [`Self::channel_allowed`] for a 6GHz profile under `six`.
    pub(super) fn channel_allowed_6ghz(
        &self,
        profile: Profile,
        six: SixGhzPower,
    ) -> Result<bool, Error> {
        self.channel_allowed_in(profile, Some(six))
    }
    fn channel_allowed_in(
        &self,
        profile: Profile,
        six: Option<SixGhzPower>,
    ) -> Result<bool, Error> {
        self.current()?;
        let envelope = if profile == Profile::INITIAL && six.is_none() {
            self.envelope
        } else {
            let Some(record) = self.channel(profile, six) else {
                return Ok(false);
            };
            record.bound(self)?;
            record.envelope
        };
        Ok(check_envelope(&*self.policy()?, envelope).is_ok())
    }
    /// `channel_allowed` restricted to spans the host rule leaves active
    /// (no DFS/NO_IR rule), where frame TX (`tx_current`) is admitted.
    pub(super) fn channel_active(&self, profile: Profile) -> Result<bool, Error> {
        self.channel_active_in(profile, None)
    }
    /// [`Self::channel_active`] for a 6GHz profile under `six`.
    pub(super) fn channel_active_6ghz(
        &self,
        profile: Profile,
        six: SixGhzPower,
    ) -> Result<bool, Error> {
        self.channel_active_in(profile, Some(six))
    }
    fn channel_active_in(&self, profile: Profile, six: Option<SixGhzPower>) -> Result<bool, Error> {
        self.current()?;
        let envelope = if profile == Profile::INITIAL && six.is_none() {
            self.envelope
        } else {
            let Some(record) = self.channel(profile, six) else {
                return Ok(false);
            };
            record.bound(self)?;
            record.envelope
        };
        Ok(check_envelope(&*self.policy()?, envelope) == Ok(false))
    }
    /// Switch the gating envelope to `profile` before its first emission.
    /// No register access happens here.
    pub(super) fn select(&self, profile: Profile) -> Result<(), Error> {
        self.select_in(profile, None)
    }
    /// [`Self::select`] for a 6GHz profile under `six`.
    pub(super) fn select_6ghz(&self, profile: Profile, six: SixGhzPower) -> Result<(), Error> {
        self.select_in(profile, Some(six))
    }
    fn select_in(&self, profile: Profile, six: Option<SixGhzPower>) -> Result<(), Error> {
        if profile != Profile::INITIAL || six.is_some() {
            self.channel(profile, six)
                .ok_or(Error::Policy)?
                .bound(self)?;
        }
        let previous = core::mem::replace(&mut *self.active.lock(), (profile, six));
        let result = self.current();
        if result.is_err() {
            *self.active.lock() = previous;
        }
        result
    }
    pub(super) fn active(&self) -> Profile {
        self.active.lock().0
    }
    /// The 6GHz power context of the active profile (`None` off 6GHz).
    pub(super) fn active_six_ghz(&self) -> Option<SixGhzPower> {
        self.active.lock().1
    }
    fn active_envelope(&self) -> Result<Envelope, Error> {
        let (active, six) = *self.active.lock();
        if active == Profile::INITIAL && six.is_none() {
            return Ok(self.envelope);
        }
        let record = self.channel(active, six).ok_or(Error::Policy)?;
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
        check_envelope(&*self.policy()?, self.active_envelope()?).map(|_| ())
    }
    /// `current` plus the frame-TX rule. A passive-only (DFS / NO_IR) span
    /// may carry the signed calibration/tuning emissions the record covers,
    /// but no frame: mac80211 never probes there, and RTL8852C has no
    /// station beacon-witness passive TX grant (B's `grant_passive_tx`), so
    /// every frame on such an active span is refused.
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
                    match *q.active.lock() {
                        (active, None) if active == Profile::INITIAL => (self.operation)(),
                        (active, six) => match q.channel(active, six) {
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
pub(super) fn check_envelope(domain: &RegulatoryDomain, envelope: Envelope) -> Result<bool, Error> {
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
        let allowed = match envelope.client {
            Some(_) => PLAIN_RULE_FLAGS | PASSIVE_RULE_FLAGS | SIX_GHZ_RULE_FLAGS,
            None => PLAIN_RULE_FLAGS | PASSIVE_RULE_FLAGS,
        };
        if rule.freq_start_mhz > covered
            || domain.max_bandwidth(index) < envelope.width
            || rule.flags.bits() & !allowed != 0
        {
            return Err(Error::Policy);
        }
        if let Some(client) = envelope.client {
            use narf_wireless::reg::RegFlags;
            // cfg80211_6ghz_power_type_valid over every rule of the span;
            // an indoor-only rule needs the trusted indoor deployment.
            if low < 5925
                || !rule.allows_6ghz_client(client)
                || (rule.flags.contains(RegFlags::INDOOR_ONLY)
                    && !rule.flags.contains(RegFlags::DEPLOYMENT_INDOOR))
                || (rule.flags.contains(RegFlags::DEPLOYMENT_INDOOR)
                    && !rule.flags.contains(RegFlags::INDOOR_ONLY))
            {
                return Err(Error::Policy);
            }
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
/// Rule flags only a 6GHz envelope may carry (each checked above).
const SIX_GHZ_RULE_FLAGS: u32 = narf_wireless::reg::RegFlags::NO_6GHZ_VLP_CLIENT.bits()
    | narf_wireless::reg::RegFlags::NO_6GHZ_AFC_CLIENT.bits()
    | narf_wireless::reg::RegFlags::INDOOR_ONLY.bits()
    | narf_wireless::reg::RegFlags::DEPLOYMENT_INDOOR.bits();
const PLAIN_RULE_FLAGS: u32 = narf_wireless::reg::RegFlags::NO_P2P.bits()
    | narf_wireless::reg::RegFlags::AUTO_BW.bits()
    | narf_wireless::reg::RegFlags::NO_160MHZ.bits();
#[cfg(any(test, feature = "kernel-test"))]
#[path = "radio_policy_c/tests.rs"]
pub(super) mod tests;
