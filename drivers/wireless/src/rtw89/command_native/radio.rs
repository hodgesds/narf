// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Full B radio qualification and source composition on the same retained
//! Native. No generic packet adapter can manufacture its ordinary receipt.
use super::*;
use crate::rtw89::{
    operating_channel, operating_channel_c, power, radio_assets, radio_c, radio_full, radio_init,
    radio_policy, radio_policy_c, radio_power, radio_power_c, rfk, tssi,
};
use alloc::sync::Arc;
pub(in crate::rtw89) struct RadioPreflight {
    board: radio_policy::Board,
    qualification: Arc<radio_policy::Qualification>,
    power: radio_power::Plan,
    tracking: tssi::Tracking,
}
/// Read-only provisioning metadata derived from actual retained hardware and
/// verified firmware inputs. This is neither authority nor a readiness receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::rtw89) struct QualificationRequest {
    version: u8,
    mac: [u8; 6],
    digest: [u8; 32],
    wmm_digest: Option<[u8; 32]>,
    qos_digest: Option<[u8; 32]>,
}
impl QualificationRequest {
    pub(in crate::rtw89) fn version(&self) -> u8 {
        self.version
    }
    pub(in crate::rtw89) fn mac(&self) -> [u8; 6] {
        self.mac
    }
    pub(in crate::rtw89) fn digest(&self) -> [u8; 32] {
        self.digest
    }
    pub(in crate::rtw89) fn wmm_digest(&self) -> Option<[u8; 32]> {
        self.wmm_digest
    }
    /// Identity for flags15 (all-AC QoS on top of WMM).
    pub(in crate::rtw89) fn qos_digest(&self) -> Option<[u8; 32]> {
        self.qos_digest
    }
    pub(in crate::rtw89) fn name(&self) -> alloc::string::String {
        let m = self.mac;
        let profile = if self.version == 1 {
            "cal-v1"
        } else {
            "radio-v2"
        };
        alloc::format!(
            "rtw89/rtw8852b-{}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}.bin",
            profile,
            m[0],
            m[1],
            m[2],
            m[3],
            m[4],
            m[5]
        )
    }
}
fn denied(_: impl core::fmt::Debug) -> power::Error {
    power::Error::Access
}
/// Typed 2.4GHz or 5GHz 20MHz primary and its Linux per-channel power plan.
fn channel_plan(
    assets: &radio_assets::Assets,
    rfe: u8,
    primary: u8,
) -> Result<(operating_channel::Profile, radio_power::Plan), power::Error> {
    let profile =
        operating_channel::Profile::from_primary(primary).ok_or(power::Error::Unsupported)?;
    profile_plan(assets, rfe, profile)
}
fn profile_plan(
    assets: &radio_assets::Assets,
    rfe: u8,
    profile: operating_channel::Profile,
) -> Result<(operating_channel::Profile, radio_power::Plan), power::Error> {
    let plan = radio_power::Plan::from_assets_for_channel(assets, rfe, profile).map_err(denied)?;
    Ok((profile, plan))
}
/// Every typed RTL8852B 40/80MHz operating channel (rtw8852b.c
/// `support_bandwidths`): 2.4GHz HT40 on either side within 1..=13 and the
/// 5GHz 40/80MHz IEEE blocks, one per primary/width/side.
pub(in crate::rtw89) fn wide_profiles() -> impl Iterator<Item = operating_channel::Profile> {
    use operating_channel::{Profile, Width};
    let ghz2 = (1..=13u8).flat_map(|primary| {
        [true, false]
            .into_iter()
            .filter_map(move |above| Profile::new_2ghz_40(primary, above))
    });
    let ghz5 = operating_channel::GHZ5.into_iter().flat_map(|primary| {
        [Width::Mhz40, Width::Mhz80]
            .into_iter()
            .filter_map(move |width| Profile::new_5ghz(primary, width))
    });
    ghz2.chain(ghz5)
}
/// The RTL8852C-only 5GHz 160MHz station chandefs (rtw8852c.c
/// `support_bandwidths` has `NL80211_CHAN_WIDTH_160`; rtw8852b.c does not),
/// one per primary of every IEEE 160MHz block wholly inside core.c
/// `rtw89_channels_5ghz`. Never offered to an RTL8852B owner.
pub(in crate::rtw89) fn wide_profiles_c160() -> impl Iterator<Item = operating_channel::Profile> {
    operating_channel::GHZ5
        .into_iter()
        .filter_map(operating_channel::Profile::new_5ghz_160)
}
/// The RTL8852C typed profile of a shared station profile (`wide_profiles`
/// or a 20MHz narrowing): same primary, center and width.
pub(in crate::rtw89) fn c_profile(
    profile: operating_channel::Profile,
) -> Option<operating_channel_c::Profile> {
    use operating_channel::Width;
    use operating_channel_c::{Band, Profile, Width as WidthC};
    let band = if profile.is_5ghz() {
        Band::Ghz5
    } else {
        Band::Ghz2
    };
    let c = match profile.width() {
        Width::Mhz20 => Profile::new20(band, profile.primary()),
        Width::Mhz40 if band == Band::Ghz2 => {
            Profile::new_2ghz_40(profile.primary(), profile.secondary_above())
        }
        Width::Mhz40 => Profile::new_wide(band, profile.primary(), WidthC::Mhz40),
        Width::Mhz80 => Profile::new_wide(band, profile.primary(), WidthC::Mhz80),
        Width::Mhz160 => Profile::new_wide(band, profile.primary(), WidthC::Mhz160),
    }?;
    (c.center() == profile.center()).then_some(c)
}
impl Native {
    /// Derive the exact required signed-artifact identity without opening any
    /// artifact, touching registers, advancing state or granting transmission.
    pub(in crate::rtw89) fn qualification_request(
        &self,
        assets: &radio_assets::Assets,
        full: bool,
    ) -> Result<QualificationRequest, power::Error> {
        crate::rtw88::pci_park::invoke(&self.authority, || {
            self.phy_profile_current()?;
            let factory = self.factory.as_ref().ok_or(power::Error::Unsupported)?;
            let identity = factory.identity().ok_or(power::Error::Unsupported)?;
            let digest = if full {
                let power = radio_power::Plan::from_assets(assets, identity.calibration().rfe_type)
                    .map_err(denied)?;
                radio_policy::Board::new_for(
                    self.lifecycle,
                    factory,
                    self.device.id,
                    assets,
                    &power,
                    self.firmware_phycap().ok_or(power::Error::Unsupported)?,
                )
                .map_err(denied)?
                .identity()
            } else {
                crate::rtw89::calibration_policy::Board::new(factory, self.device.id, assets)
                    .map_err(denied)?
                    .identity()
            };
            Ok(QualificationRequest {
                version: if full { 2 } else { 1 },
                mac: identity.mac(),
                digest,
                wmm_digest: if full {
                    let power =
                        radio_power::Plan::from_assets(assets, identity.calibration().rfe_type)
                            .map_err(denied)?;
                    Some(
                        radio_policy::Board::new_for(
                            self.lifecycle,
                            factory,
                            self.device.id,
                            assets,
                            &power,
                            self.firmware_phycap().ok_or(power::Error::Unsupported)?,
                        )
                        .map_err(denied)?
                        .wmm()
                        .identity(),
                    )
                } else {
                    None
                },
                qos_digest: if full {
                    let power =
                        radio_power::Plan::from_assets(assets, identity.calibration().rfe_type)
                            .map_err(denied)?;
                    Some(
                        radio_policy::Board::new_for(
                            self.lifecycle,
                            factory,
                            self.device.id,
                            assets,
                            &power,
                            self.firmware_phycap().ok_or(power::Error::Unsupported)?,
                        )
                        .map_err(denied)?
                        .with_programs(radio_policy::Program::QosAll.flags())
                        .identity(),
                    )
                } else {
                    None
                },
            })
        })
        .map_err(denied)?
    }
    /// A C operating program the signed C base record enables
    /// (`radio_policy_c::PROGRAMS`: WMM, all-AC QoS, firmware RA, HT20,
    /// HE20 and originator A-MPDU).
    /// RTL8851B: the signed `N51B` v2 base record's programs
    /// (`radio_policy_51::PROGRAMS`).
    fn c_program(&self, program: radio_policy::Program) -> Result<bool, power::Error> {
        if self.chip == ChipId::Rtl8851B {
            return self
                .qualification_51
                .as_ref()
                .ok_or(power::Error::Unsupported)?
                .allows(program)
                .map_err(|_| power::Error::Access);
        }
        self.qualification_c
            .as_ref()
            .ok_or(power::Error::Unsupported)?
            .allows(program)
            .map_err(|_| power::Error::Access)
    }
    /// RTL8852C or RTL8851B with its current ordinary grant: the B
    /// companion program neither has a path for (A-MSDU) is "no program"
    /// (`Ok(false)`); the base record programs follow `c_program`.
    /// B (or no grant) is `Ok(false)` here and keeps its own checks.
    fn c_ordinary(&self) -> Result<bool, power::Error> {
        if !matches!(self.chip, ChipId::Rtl8852C | ChipId::Rtl8851B) {
            return Ok(false);
        }
        self.ordinary_current()?;
        Ok(true)
    }
    pub(in crate::rtw89) fn station_ht_allowed(&self) -> Result<bool, power::Error> {
        if self.c_ordinary()? {
            return self.c_program(radio_policy::Program::Ht);
        }
        self.full_radio_scope()
            .ok_or(power::Error::Unsupported)?
            .allows(radio_policy::Program::Ht)
            .map_err(denied)
    }
    pub(in crate::rtw89) fn station_he_allowed(&self) -> Result<bool, power::Error> {
        if self.c_ordinary()? {
            return self.c_program(radio_policy::Program::He);
        }
        self.full_radio_scope()
            .ok_or(power::Error::Unsupported)?
            .allows(radio_policy::Program::He)
            .map_err(denied)
    }
    /// Track-work register access for the live station (`track.rs`): only
    /// the listed CCX/DIG/EDCCA/PPDU-status registers, on the prepared
    /// operating PHY and current ordinary authority.
    fn track_port(&mut self, address: u32) -> Result<Port<'_>, power::Error> {
        if self.sleep_blocked {
            return Err(power::Error::Terminal);
        }
        crate::rtw89::station_control::awake(&mut self.io)?;
        let registers: &[u32] = if self.chip == ChipId::Rtl8852C {
            &crate::rtw89::track::REGISTERS_C
        } else if self.chip == ChipId::Rtl8851B {
            &crate::rtw89::track::REGISTERS_51
        } else {
            &crate::rtw89::track::REGISTERS
        };
        if !registers.contains(&address) {
            return Err(power::Error::Access);
        }
        self.track_operating_current()?;
        self.radio_io()
    }
    /// Chip dispatch of `operating_current` for track work. C: the current
    /// C ordinary grant, the C factory/PHY-capability receipt and the C
    /// operating owner `phy_operating::Operating::prepare_c` prepared from
    /// the same identity (`support_cckpd` true on every C cut). RTL8851B:
    /// likewise its own ordinary grant, factory/receipt and the B-sequence
    /// operating owner (`support_cckpd` true on every RTL8851B cut).
    fn track_operating_current(&self) -> Result<(), power::Error> {
        if !matches!(self.chip, ChipId::Rtl8852C | ChipId::Rtl8851B) {
            return self.operating_current();
        }
        self.radio_profile_current()?;
        if !self.c_ordinary()? {
            return Err(power::Error::Unsupported);
        }
        let actual = self
            .factory
            .as_ref()
            .and_then(|f| f.identity())
            .ok_or(power::Error::Unsupported)?;
        let owner = self.operating.as_ref().ok_or(power::Error::Terminal)?;
        let working = owner.working().ok_or(power::Error::Unsupported)?;
        if owner.state() != crate::rtw89::phy_operating::State::Prepared
            || working.cut != actual.cut()
            || working.rfe != actual.calibration().rfe_type
            || working.crystal_cap != actual.xtal() & 0x7f
            || !working.cck_pd
        {
            return Err(power::Error::Unsupported);
        }
        Ok(())
    }
    /// Track-work chip layout and whether the active channel is 5 GHz
    /// (B: its 2.4 GHz channel-1 profile; C: the active signed profile).
    pub(in crate::rtw89) fn station_track_layout(
        &self,
    ) -> Result<(crate::rtw89::track::Layout, bool), power::Error> {
        if self.chip == ChipId::Rtl8851B {
            self.track_operating_current()?;
            let active = self
                .qualification_51
                .as_ref()
                .ok_or(power::Error::Unsupported)?
                .active();
            return Ok((crate::rtw89::track::LAYOUT_51, active.is_5ghz()));
        }
        if self.chip != ChipId::Rtl8852C {
            return Ok((crate::rtw89::track::LAYOUT_B, false));
        }
        self.track_operating_current()?;
        let active = self
            .qualification_c
            .as_ref()
            .ok_or(power::Error::Unsupported)?
            .active();
        Ok((
            crate::rtw89::track::LAYOUT_C,
            active.band() == operating_channel_c::Band::Ghz5,
        ))
    }
    pub(in crate::rtw89) fn station_track_read(
        &mut self,
        address: u32,
    ) -> Result<u32, power::Error> {
        use power::Io as _;
        self.track_port(address)?.read32(address)
    }
    pub(in crate::rtw89) fn station_track_write(
        &mut self,
        address: u32,
        value: u32,
    ) -> Result<(), power::Error> {
        use power::Io as _;
        self.track_port(address)?.write32(address, value)
    }
    pub(in crate::rtw89) fn station_track_profile(
        &self,
    ) -> Result<crate::rtw89::track::Profile, power::Error> {
        if self.sleep_blocked {
            return Err(power::Error::Terminal);
        }
        self.track_operating_current()?;
        let working = self
            .operating
            .as_ref()
            .and_then(|owner| owner.working())
            .ok_or(power::Error::Unsupported)?;
        Ok(crate::rtw89::track::Profile {
            cck_pd: working.cck_pd,
            crystal_cap: working.crystal_cap,
            crystal_lower: working.crystal_lower,
            crystal_upper: working.crystal_upper,
        })
    }
    /// `rtw89_phy_cfo_set_crystal_cap` (B and C: `xtal_info` NULL, the
    /// non-8852A/8851B branch): XTAL SI SC_XO (0x05) then SC_XI (0x04),
    /// full byte masks, then read both back.
    pub(in crate::rtw89) async fn station_track_crystal(
        &mut self,
        cap: u8,
    ) -> Result<u8, power::Error> {
        // Linux clamps to 0..=127; the divergence lock bounds the excursion.
        self.station_track_profile()?;
        if cap > 0x7f {
            return Err(power::Error::Access);
        }
        if self.chip == ChipId::Rtl8851B {
            return self.station_track_crystal_51(cap);
        }
        let mut port = self.radio_io()?;
        // SAFETY: the retained exclusive B owner serializes every XTAL SI
        // transaction (track work runs under the station's retained lock);
        // Port encloses each access in current ordinary/device authority.
        unsafe {
            crate::rtw89::radio_shutdown::xtal_write(&mut port, 0x05, cap, 0xff).await?;
            crate::rtw89::radio_shutdown::xtal_write(&mut port, 0x04, cap, 0xff).await?;
            let xo = crate::rtw89::radio_shutdown::xtal_read(&mut port, 0x05).await?;
            let xi = crate::rtw89::radio_shutdown::xtal_read(&mut port, 0x04).await?;
            if xo != cap || xi != cap {
                return Err(power::Error::Terminal);
            }
            Ok(xi)
        }
    }
    /// phy.c `rtw89_phy_cfo_set_crystal_cap` RTL8851B branch
    /// (`rtw8851b_xtal_info`): `R_AX_XTAL_ON_CTRL3` (0x28c) SC_XO
    /// [14:8] then SC_XI [6:0] masked writes, then read both back.
    fn station_track_crystal_51(&mut self, cap: u8) -> Result<u8, power::Error> {
        use power::Io as _;
        const R_AX_XTAL_ON_CTRL3: u32 = 0x028c;
        const SC_XO: u32 = 0x7f00;
        const SC_XI: u32 = 0x007f;
        let mut port = self.radio_io()?;
        for mask in [SC_XO, SC_XI] {
            let old = port.read32(R_AX_XTAL_ON_CTRL3)?;
            if old == u32::MAX {
                return Err(power::Error::Gone);
            }
            let new = (old & !mask) | ((u32::from(cap) << mask.trailing_zeros()) & mask);
            port.write32(R_AX_XTAL_ON_CTRL3, new)?;
        }
        let value = port.read32(R_AX_XTAL_ON_CTRL3)?;
        let xo = ((value & SC_XO) >> SC_XO.trailing_zeros()) as u8;
        let xi = (value & SC_XI) as u8;
        if value == u32::MAX || xo != cap || xi != cap {
            return Err(power::Error::Terminal);
        }
        Ok(xi)
    }
    pub(in crate::rtw89) fn station_ampdu_allowed(&self) -> Result<bool, power::Error> {
        if self.c_ordinary()? {
            return self.c_program(radio_policy::Program::Ampdu);
        }
        self.full_radio_scope()
            .ok_or(power::Error::Unsupported)?
            .allows(radio_policy::Program::Ampdu)
            .map_err(denied)
    }
    pub(in crate::rtw89) fn station_firmware_ra_allowed(&self) -> Result<bool, power::Error> {
        if self.c_ordinary()? {
            return self.c_program(radio_policy::Program::FirmwareRa);
        }
        self.full_radio_scope()
            .ok_or(power::Error::Unsupported)?
            .allows(radio_policy::Program::FirmwareRa)
            .map_err(denied)
    }
    pub(in crate::rtw89) fn station_amsdu_allowed(&self) -> Result<bool, power::Error> {
        if self.c_ordinary()? {
            return Ok(false);
        }
        self.full_radio_scope()
            .ok_or(power::Error::Unsupported)?
            .amsdu_allowed()
            .map_err(denied)
    }
    pub(in crate::rtw89) fn station_qos_all_allowed(&self) -> Result<bool, power::Error> {
        if self.c_ordinary()? {
            return self.c_program(radio_policy::Program::QosAll);
        }
        self.full_radio_scope()
            .ok_or(power::Error::Unsupported)?
            .allows(radio_policy::Program::QosAll)
            .map_err(denied)
    }
    pub(in crate::rtw89) fn station_wmm_allowed(&self) -> Result<bool, power::Error> {
        if self.c_ordinary()? {
            return self.c_program(radio_policy::Program::Wmm);
        }
        self.full_radio_scope()
            .ok_or(power::Error::Unsupported)?
            .wmm_allowed()
            .map_err(denied)
    }
    fn operating_current(&self) -> Result<(), power::Error> {
        self.phy_profile_current()?;
        let actual = self
            .factory
            .as_ref()
            .and_then(|f| f.identity())
            .ok_or(power::Error::Unsupported)?;
        let owner = self.operating.as_ref().ok_or(power::Error::Terminal)?;
        let working = owner.working().ok_or(power::Error::Unsupported)?;
        if owner.state() != crate::rtw89::phy_operating::State::Prepared
            || working.cut != actual.cut()
            || working.rfe != actual.calibration().rfe_type
            || working.crystal_cap != actual.xtal() & 0x7f
            || working.cck_pd != (actual.cut() > 0)
        {
            return Err(power::Error::Unsupported);
        }
        Ok(())
    }
    /// Pure asset/current-authority staging; missing signed v2 remains retryable
    /// before Startup creates its next terminal hardware Attempt.
    pub(in crate::rtw89) fn preflight_full_radio(
        &self,
        tables: &radio_init::Init,
        basic: &rfk::Rfk,
        assets: &radio_assets::Assets,
    ) -> Result<RadioPreflight, power::Error> {
        crate::rtw88::pci_park::invoke(&self.authority, || {
            self.phy_profile_current()?;
            self.operating_current()?;
            if self.state != State::Active
                || self.chip != ChipId::Rtl8852B
                || !self.nctl_ready
                || !self.coex_ready
                || self.ordinary.is_some()
                || self.full_qualification.is_some()
                || tables.state() != radio_init::State::TablesLoaded
                || basic.results().is_none()
                || self.gain_bases.is_none()
            {
                return Err(power::Error::Terminal);
            }
            self.calibration
                .as_ref()
                .ok_or(power::Error::Access)?
                .current()
                .map_err(denied)?;
            let factory = self.factory.as_ref().ok_or(power::Error::Unsupported)?;
            let identity = factory.identity().ok_or(power::Error::Unsupported)?;
            let plan = radio_power::Plan::from_assets(assets, identity.calibration().rfe_type)
                .map_err(denied)?;
            let tracking = tssi::Tracking::from_assets(assets).map_err(denied)?;
            let board = radio_policy::Board::new_for(
                self.lifecycle,
                factory,
                self.device.id,
                assets,
                &plan,
                self.firmware_phycap().ok_or(power::Error::Unsupported)?,
            )
            .map_err(denied)?;
            let mut qualification = radio_policy::Qualification::load(board).map_err(denied)?;
            qualification.load_sleep(assets).map_err(denied)?;
            qualification.load_fragments().map_err(denied)?;
            // Optional signed N52C per-channel full programs, loaded last so
            // each binds every installed companion. Absent records leave
            // that primary unadmitted; channel14 is never loaded.
            let narrow = (2..=13)
                .chain(operating_channel::GHZ5)
                .filter_map(operating_channel::Profile::from_primary);
            for profile in narrow.chain(wide_profiles()) {
                let (profile, plan) =
                    profile_plan(assets, identity.calibration().rfe_type, profile)?;
                let board = radio_policy::Board::new_noninitial(
                    self.lifecycle,
                    factory,
                    self.device.id,
                    assets,
                    &plan,
                    self.firmware_phycap().ok_or(power::Error::Unsupported)?,
                )
                .map_err(denied)?;
                qualification.load_channel(profile, board).map_err(denied)?;
            }
            qualification.current().map_err(denied)?;
            Ok(RadioPreflight {
                board,
                qualification: Arc::new(qualification),
                power: plan,
                tracking,
            })
        })
        .map_err(denied)?
    }
    /// # Safety
    /// Same actual retained Startup/table/basic owners and exclusive one-shot
    /// initial channel/radio lifecycle; outer Attempt closes all engines and
    /// retains every uncertain mapping on failure/cancel. No packet starts until
    /// this function earns and installs its sealed ordinary receipt.
    pub(in crate::rtw89) async unsafe fn prepare_full_radio(
        &mut self,
        owner: &mut radio_full::Radio,
        tables: &radio_init::Init,
        basic: &rfk::Rfk,
        assets: &radio_assets::Assets,
        preflight: RadioPreflight,
    ) -> Result<(), power::Error> {
        self.phy_profile_current()?;
        self.operating_current()?;
        self.radio_access()?;
        if owner.state() != radio_full::State::New
            || self.ordinary.is_some()
            || self.full_qualification.is_some()
            || !self.coex_ready
            || !self.nctl_ready
        {
            return Err(power::Error::Terminal);
        }
        let factory = self.factory.as_ref().ok_or(power::Error::Unsupported)?;
        let identity = factory.identity().ok_or(power::Error::Unsupported)?;
        let plan = radio_power::Plan::from_assets(assets, identity.calibration().rfe_type)
            .map_err(denied)?;
        let tracking = tssi::Tracking::from_assets(assets).map_err(denied)?;
        let board = radio_policy::Board::new_for(
            self.lifecycle,
            factory,
            self.device.id,
            assets,
            &plan,
            self.firmware_phycap().ok_or(power::Error::Unsupported)?,
        )
        .map_err(denied)?;
        if board != preflight.board
            || !preflight.qualification.matches(board)
            || plan != preflight.power
            || tracking != preflight.tracking
        {
            return Err(power::Error::Access);
        }
        preflight.qualification.current().map_err(denied)?;
        let gain = tables.gain().ok_or(power::Error::Unsupported)?.clone();
        let calibration = *tables.calibration().ok_or(power::Error::Unsupported)?;
        if crate::rtw89::factory_b::Calibration::from_factory(factory) != Some(calibration) {
            return Err(power::Error::Access);
        }
        let bases = self.gain_bases.ok_or(power::Error::Unsupported)?;
        let dpd_gain = basic.results().ok_or(power::Error::Unsupported)?.dpd_gain;
        let cut = identity.cut();
        self.full_qualification = Some(preflight.qualification);
        // The expanded receipt independently covers the entire basic/full recipe.
        // Once installed all subsequent source transitions use this retained v2 cap.
        self.calibration = None;
        // SAFETY: all inputs above rebound to this exact actual Native and assets;
        // the one owner is retained by Startup across every async engine operation.
        unsafe {
            owner
                .prepare(
                    self,
                    radio_full::Inputs {
                        gain: &gain,
                        calibration: &calibration,
                        gain_bases: bases,
                        cut,
                        dpd_gain,
                        power: &preflight.power,
                        tracking: &preflight.tracking,
                    },
                )
                .await
        }?;
        // Source B RF_GET_MCCCH format (no V0 feature for B): first fresh table has
        // channel1 in slot0 and zero slot1. Consumption is not an execution receipt.
        self.runtime_command(2, 0x0a, 2, &mccch(1), false, super::station::Permit::Legacy)
            .await?;
        self.phy_profile_current()?;
        if owner.state() != radio_full::State::Ready {
            return Err(power::Error::Terminal);
        }
        let qualification = self.full_qualification.take().ok_or(power::Error::Access)?;
        qualification.current().map_err(denied)?;
        if qualification
            .rf_tracking_window()
            .map_err(denied)?
            .is_some()
        {
            let input = owner.tracking_inputs().ok_or(power::Error::Terminal)?;
            self.station_runtime.rf_tracking = Some(crate::rtw89::rf_tracking::Tracker::new(input));
        }
        self.channel = Some((OperatingChannel::legacy(1), owner.epoch()));
        self.ordinary = Some(OrdinaryGrant::B(qualification));
        Ok(())
    }
}

/// Source B RF_GET_MCCCH body (no V0 feature for B): `rtw89_fw_h2c_rf_ntfy_mcc`
/// with `rtw89_rfk_chan_lookup` replacing slot0 for the single entity, so
/// ch_0_0 = ch_0_1 = current = primary and slot1 stays zero.
/// RF_GET_MCCCH channels are `rfk_mcc->ch[]` = `chan->channel` (the center
/// channel; equal to the primary at 20MHz).
fn mccch(primary: u8) -> [u8; 20] {
    let mut mcc = [0u8; 20];
    for at in [0, 4, 16] {
        mcc[at..at + 4].copy_from_slice(&u32::from(primary).to_le_bytes());
    }
    mcc
}
/// One admitted RTL8852C 6GHz 20MHz operating channel under one regd.c
/// power context (`Native::admitted_six_ghz`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::rtw89) struct SixGhzChannel {
    pub(in crate::rtw89) primary: u8,
    pub(in crate::rtw89) six: crate::rtw89::radio_power_c::SixGhzPower,
    /// The cfg80211 client power type the record admits.
    pub(in crate::rtw89) power: narf_wireless::reg::PowerType6Ghz,
    /// No DFS/NO_IR rule over the span: probe/association frames may follow.
    pub(in crate::rtw89) active: bool,
}
impl Native {
    /// Compact mask (`operating_channel::slot`: 2.4GHz primary n = bit n,
    /// 5GHz after) of primaries with a current signed full program whose
    /// host rule currently permits active emission.
    pub(in crate::rtw89) fn admitted_channels(&self) -> Result<u64, power::Error> {
        if self.c_ordinary()? {
            if self.chip == ChipId::Rtl8851B {
                return self.admitted_channels_51();
            }
            return self.admitted_channels_c();
        }
        let qualification = self.full_radio_scope().ok_or(power::Error::Unsupported)?;
        let mut mask = 0;
        for primary in (1..=13).chain(operating_channel::GHZ5) {
            let profile = operating_channel::Profile::from_primary(primary)
                .ok_or(power::Error::Unsupported)?;
            let bit = operating_channel::slot(primary).ok_or(power::Error::Unsupported)?;
            if qualification.channel_allowed(profile).map_err(denied)? {
                mask |= 1u64 << bit;
            }
        }
        Ok(mask)
    }
    /// RTL8851B station mask over the 20MHz profile of every 2.4GHz
    /// (1..=13) and 5GHz primary with a loaded signed record whose host rule
    /// currently permits active emission (`channel_active`; RTL8851B has no
    /// beacon-witness passive TX grant either). Channel 14 has no record.
    fn admitted_channels_51(&self) -> Result<u64, power::Error> {
        let qualification = self
            .qualification_51
            .as_ref()
            .ok_or(power::Error::Terminal)?;
        let mut mask = 0;
        for primary in (1..=13).chain(operating_channel::GHZ5) {
            let Some(profile) = operating_channel::Profile::from_primary(primary) else {
                continue;
            };
            let bit = operating_channel::slot(primary).ok_or(power::Error::Unsupported)?;
            if qualification.channel_active(profile).map_err(denied)? {
                mask |= 1u64 << bit;
            }
        }
        Ok(mask)
    }
    /// RTL8852C station mask over the 20MHz profile of every 2.4GHz (1..=13)
    /// and 5GHz primary: a loaded signed record whose host rule currently
    /// permits active emission. Passive-only (DFS/NO_IR) spans are left out:
    /// C has no beacon-witness passive TX grant, so no frame could follow.
    fn admitted_channels_c(&self) -> Result<u64, power::Error> {
        let qualification = self
            .qualification_c
            .as_ref()
            .ok_or(power::Error::Terminal)?;
        let mut mask = 0;
        for primary in (1..=13).chain(operating_channel::GHZ5) {
            let band = if primary <= 14 {
                operating_channel_c::Band::Ghz2
            } else {
                operating_channel_c::Band::Ghz5
            };
            let Some(profile) = operating_channel_c::Profile::new20(band, primary) else {
                continue;
            };
            let bit = operating_channel::slot(primary).ok_or(power::Error::Unsupported)?;
            if qualification.channel_active(profile).map_err(denied)? {
                mask |= 1u64 << bit;
            }
        }
        Ok(mask)
    }
    /// Every 40/80MHz (RTL8852C: also 5GHz 160MHz) operating channel with a
    /// current signed full program
    /// whose host rule currently permits it (scan/association may widen to
    /// exactly these; nothing wider than a record is ever programmed).
    pub(in crate::rtw89) fn admitted_wide(
        &self,
    ) -> Result<alloc::vec::Vec<operating_channel::Profile>, power::Error> {
        if self.c_ordinary()? && self.chip == ChipId::Rtl8851B {
            // RTL8851B: the same 40/80MHz chandefs (`support_bandwidths`
            // 20/40/80), each with a loaded signed `N51C` record wholly
            // active under the host rule.
            let qualification = self
                .qualification_51
                .as_ref()
                .ok_or(power::Error::Terminal)?;
            let mut admitted = alloc::vec::Vec::new();
            for profile in wide_profiles() {
                if qualification.channel_active(profile).map_err(denied)? {
                    admitted.push(profile);
                }
            }
            return Ok(admitted);
        }
        if self.c_ordinary()? {
            // RTL8852C: the same 40/80MHz chandefs plus the C-only 5GHz
            // 160MHz ones, each with a loaded signed `N5CC` record wholly
            // active under the host rule.
            let qualification = self
                .qualification_c
                .as_ref()
                .ok_or(power::Error::Terminal)?;
            let mut admitted = alloc::vec::Vec::new();
            for profile in wide_profiles().chain(wide_profiles_c160()) {
                let Some(c) = c_profile(profile) else {
                    continue;
                };
                if qualification.channel_active(c).map_err(denied)? {
                    admitted.push(profile);
                }
            }
            return Ok(admitted);
        }
        // RTL8852C wide operating channels belong to its own C records.
        if self.c_ordinary()? {
            return Ok(alloc::vec::Vec::new());
        }
        let qualification = self.full_radio_scope().ok_or(power::Error::Unsupported)?;
        let mut admitted = alloc::vec::Vec::new();
        for profile in wide_profiles() {
            if qualification.channel_allowed(profile).map_err(denied)? {
                admitted.push(profile);
            }
        }
        Ok(admitted)
    }
    /// RTL8852C 6GHz 20MHz operating channels: every typed 6GHz primary
    /// whose 20MHz profile has a loaded signed `N5CC` record under a regd.c
    /// power context (`six_ghz_contexts`) the current host rule admits
    /// (`channel_allowed_6ghz`), with whether that span is also active
    /// (`channel_active_6ghz`: no DFS/NO_IR rule, so frame TX may follow).
    /// Anything but a current C ordinary owner admits none.
    pub(in crate::rtw89) fn admitted_six_ghz(
        &self,
    ) -> Result<alloc::vec::Vec<SixGhzChannel>, power::Error> {
        let mut admitted = alloc::vec::Vec::new();
        // RTL8851B `support_bands` has no 6GHz.
        if !self.c_ordinary()? || self.chip != ChipId::Rtl8852C {
            return Ok(admitted);
        }
        let qualification = self
            .qualification_c
            .as_ref()
            .ok_or(power::Error::Terminal)?;
        for primary in (1..=233).filter(|&p| operating_channel_c::is_6ghz_primary(p)) {
            let Some(profile) =
                operating_channel_c::Profile::new20(operating_channel_c::Band::Ghz6, primary)
            else {
                continue;
            };
            for six in qualification.six_ghz_contexts(profile) {
                if !qualification
                    .channel_allowed_6ghz(profile, six)
                    .map_err(denied)?
                {
                    continue;
                }
                admitted.push(SixGhzChannel {
                    primary,
                    six,
                    power: crate::rtw89::radio_policy_c::client_type(six),
                    active: qualification
                        .channel_active_6ghz(profile, six)
                        .map_err(denied)?,
                });
            }
        }
        Ok(admitted)
    }
    /// The host policy snapshot the RTL8852C 6GHz records are checked
    /// against (the rule a 6GHz join is planned under). `None` off C.
    pub(in crate::rtw89) fn six_ghz_regulatory(
        &self,
    ) -> Result<Option<Arc<narf_wireless::reg::RegulatoryDomain>>, power::Error> {
        if !self.c_ordinary()? || self.chip != ChipId::Rtl8852C {
            return Ok(None);
        }
        self.qualification_c
            .as_ref()
            .ok_or(power::Error::Terminal)?
            .policy()
            .map(Some)
            .map_err(denied)
    }
    /// Band-qualified channel and retune epoch of the last completed full
    /// program.
    pub(in crate::rtw89) fn operating_channel(&self) -> Option<(OperatingChannel, u32)> {
        self.ordinary.as_ref()?;
        self.channel
    }
    /// Native retune owner for one noninitial (or back to the initial)
    /// 2.4GHz/20MHz primary on the Ready radio.
    ///
    /// `linked` is the associated-station channel switch (mac80211
    /// `ieee80211_csa_switch_work` -> `ieee80211_link_use_reserved_context`
    /// -> rtw89 `rtw89_ops_switch_vif_chanctx`/`rtw89_chanctx_ops_reassign_vif`
    /// -> `rtw89_set_channel`): the installed peer (firmware role/join/CMAC/
    /// RA/BA CAM, all channel-independent on 8852B 2.4GHz/20MHz) must exist
    /// and stays installed; without it no peer may exist. Every other
    /// precondition below is identical, so no ordinary TX/RX is in flight.
    ///
    /// Mirrors mac80211 `ieee80211_offchannel_stop_vifs` + `drv_flush`
    /// (rtw89_ops_flush: leave LPS, flush HCI/MAC queues) then
    /// `rtw89_ops_config` (`rtw89_leave_ps_mode`, `rtw89_config_entity_chandef`,
    /// core.c `rtw89_set_channel`) and `rtw89_chip_rfk_channel` (rtw8852b.c
    /// `rtw8852b_rfk_channel` ending in `rtw89_fw_h2c_rf_ntfy_mcc`), then
    /// `ieee80211_offchannel_return` reopening queues. Refused (with nothing
    /// published) unless ordinary TX, the H2C queue and RX backlog are drained,
    /// the radio is awake, and no peer, monitor or sleep owner exists, so no
    /// LPS/monitor/station consumer holds results of the previous primary.
    /// The ordinary grant is withheld for the whole program: the channel
    /// transition bracket (`rtw8852bx_set_channel_help` enter: stop all CMAC
    /// scheduler TX, PPDU status off, ADC off, BB reset) closes CMAC TX and
    /// every autonomous response until `finish`.
    ///
    /// # Safety
    /// Same retained Startup owner/tables/assets that prepared `owner`. A
    /// failed or dropped future leaves the radio non-Ready; the caller's
    /// Attempt terminalizes this Native.
    pub(in crate::rtw89) async unsafe fn retune_full_radio(
        &mut self,
        owner: &mut radio_full::Radio,
        tables: &radio_init::Init,
        basic: &rfk::Rfk,
        assets: &radio_assets::Assets,
        primary: u8,
        linked: bool,
    ) -> Result<u32, power::Error> {
        let profile =
            operating_channel::Profile::from_primary(primary).ok_or(power::Error::Unsupported)?;
        // SAFETY: caller contract, unchanged.
        unsafe {
            self.retune_full_radio_to(owner, tables, basic, assets, profile, linked)
                .await
        }
    }
    /// [`Self::retune_full_radio`] to an exact typed operating channel,
    /// including a signed-admitted 40/80MHz chandef (core.c
    /// `rtw89_set_channel` with `chan->band_width`/`pri_ch_idx`): the
    /// MAC/BB/RF/power/RFK program is the target width's own, never a
    /// narrowed or widened alias, and no wider span than its record is used.
    ///
    /// # Safety
    /// Same as [`Self::retune_full_radio`].
    pub(in crate::rtw89) async unsafe fn retune_full_radio_to(
        &mut self,
        owner: &mut radio_full::Radio,
        tables: &radio_init::Init,
        basic: &rfk::Rfk,
        assets: &radio_assets::Assets,
        profile: operating_channel::Profile,
        linked: bool,
    ) -> Result<u32, power::Error> {
        let primary = profile.primary();
        self.phy_profile_current()?;
        self.operating_current()?;
        self.ordinary_current()?;
        if owner.state() != radio_full::State::Ready
            || self.full_qualification.is_some()
            || !self.coex_ready
            || !self.nctl_ready
        {
            return Err(power::Error::Terminal);
        }
        let factory = self.factory.as_ref().ok_or(power::Error::Unsupported)?;
        let identity = factory.identity().ok_or(power::Error::Unsupported)?;
        let rfe = identity.calibration().rfe_type;
        let (profile, plan) = profile_plan(assets, rfe, profile)?;
        if owner.channel() == Some(profile) {
            return Ok(owner.epoch());
        }
        let qualification = self
            .ordinary
            .as_ref()
            .ok_or(power::Error::Terminal)?
            .b()
            .ok_or(power::Error::Unsupported)?
            .clone();
        if !qualification.channel_allowed(profile).map_err(denied)? {
            return Err(power::Error::Unsupported);
        }
        // Rebind the signed identity to this exact factory/assets/plan.
        let phycap = self.firmware_phycap().ok_or(power::Error::Unsupported)?;
        let fresh = if profile == operating_channel::Profile::INITIAL {
            radio_policy::Board::new_for(
                self.lifecycle,
                factory,
                self.device.id,
                assets,
                &plan,
                phycap,
            )
            .is_ok_and(|board| qualification.matches(board))
        } else {
            radio_policy::Board::new_noninitial(
                self.lifecycle,
                factory,
                self.device.id,
                assets,
                &plan,
                phycap,
            )
            .is_ok_and(|board| qualification.channel_matches(profile, board))
        };
        let tracking = tssi::Tracking::from_assets(assets).map_err(denied)?;
        if !fresh {
            return Err(power::Error::Access);
        }
        let gain = tables.gain().ok_or(power::Error::Unsupported)?.clone();
        let calibration = *tables.calibration().ok_or(power::Error::Unsupported)?;
        if crate::rtw89::factory_b::Calibration::from_factory(factory) != Some(calibration) {
            return Err(power::Error::Access);
        }
        let bases = self.gain_bases.ok_or(power::Error::Unsupported)?;
        let dpd_gain = basic.results().ok_or(power::Error::Unsupported)?.dpd_gain;
        let cut = identity.cut();
        // Drain: rtw89_ops_flush / ieee80211_offchannel_stop_vifs. Busy is a
        // proven-unpublished refusal; the caller retries after draining.
        self.poll().map_err(|_| power::Error::Access)?;
        if self.sleep_blocked
            || self.sleep_reset.is_some()
            || self.station_runtime.peer.is_some() != linked
            || self.station_runtime.monitor.is_some()
            || self.queue.pending() != 0
            || !self.station_runtime.backlog.is_empty()
            || self
                .station_runtime
                .core
                .as_ref()
                .is_some_and(|core| !core.ready())
        {
            return Err(power::Error::Busy);
        }
        // rtw89_leave_ps_mode precondition: actual CPWM/MACID0 awake.
        crate::rtw89::station_control::awake(&mut self.io)?;
        // Close ordinary publication; RFK/PMAC run in the full scope whose
        // envelope is the target primary's signed record and host span.
        let grant = self.ordinary.take().ok_or(power::Error::Terminal)?;
        self.channel = None;
        self.station_runtime.rf_tracking = None;
        qualification.select(profile).map_err(denied)?;
        self.full_qualification = Some(qualification.clone());
        // SAFETY: caller contract; queues drained and grant withheld above.
        unsafe {
            owner
                .retune(
                    self,
                    radio_full::Inputs {
                        gain: &gain,
                        calibration: &calibration,
                        gain_bases: bases,
                        cut,
                        dpd_gain,
                        power: &plan,
                        tracking: &tracking,
                    },
                )
                .await
        }?;
        self.runtime_command(
            2,
            0x0a,
            2,
            &mccch(profile.center()),
            false,
            super::station::Permit::Legacy,
        )
        .await?;
        self.phy_profile_current()?;
        if owner.state() != radio_full::State::Ready || owner.channel() != Some(profile) {
            return Err(power::Error::Terminal);
        }
        let qualification = self.full_qualification.take().ok_or(power::Error::Access)?;
        qualification.current().map_err(denied)?;
        // Republish: periodic DPK restarts from this program's fresh DPK
        // baseline; no earlier-channel thermal average survives.
        if qualification
            .rf_tracking_window()
            .map_err(denied)?
            .is_some()
        {
            let input = owner.tracking_inputs().ok_or(power::Error::Terminal)?;
            self.station_runtime.rf_tracking = Some(crate::rtw89::rf_tracking::Tracker::new(input));
        }
        self.channel = Some((OperatingChannel::legacy(primary), owner.epoch()));
        // RX admission follows the programmed width: up to this channel's
        // bandwidth, and VHT rates only on a 5GHz 40/80MHz channel.
        if let Some(core) = self.station_runtime.core.as_mut() {
            let width = profile.width() as u8;
            core.set_operating_width(width, width != 0 && profile.is_5ghz());
        }
        // ieee80211_offchannel_return: queues reopen only on the new grant.
        self.ordinary = Some(grant);
        Ok(owner.epoch())
    }
}

/// Actual register operations stay inside the signed emission capability,
/// including analog command transactions separated by async hardware waits.
/// Closing/teardown uses NativeIo directly and never needs an emission grant.
pub(super) struct Port<'a> {
    io: &'a mut NativeIo,
    basic: Option<&'a crate::rtw89::calibration_policy::Calibration>,
    full: Option<Arc<radio_policy::Qualification>>,
    chip: Option<ChipProgram>,
}
/// The chip-specific signed full program (RTL8852A `N5AB` v2 + `N5AC`,
/// RTL8852C `N5CB` v2 + `N5CC`, RTL8851B `N51B` v2 + `N51C`) that encloses
/// the calibration scope.
#[derive(Clone)]
pub(super) enum ChipProgram {
    A(Arc<crate::rtw89::radio_policy_a::Qualification>),
    C(Arc<radio_policy_c::Qualification>),
    N51(Arc<crate::rtw89::radio_policy_51::Qualification>),
}
impl<'a> Port<'a> {
    pub(super) fn new(
        io: &'a mut NativeIo,
        basic: Option<&'a crate::rtw89::calibration_policy::Calibration>,
        full: Option<Arc<radio_policy::Qualification>>,
        chip: Option<ChipProgram>,
    ) -> Self {
        Self {
            io,
            basic,
            full,
            chip,
        }
    }
    fn current<T>(
        &mut self,
        operation: impl FnOnce(&mut NativeIo) -> Result<T, power::Error>,
    ) -> Result<T, power::Error> {
        // RTL8852A / RTL8852C / RTL8851B: the signed chip full program
        // encloses the calibration scope.
        match self.chip.clone() {
            Some(ChipProgram::A(a)) => a.with_current(|| self.current_b(operation)),
            Some(ChipProgram::C(c)) => c.with_current(|| self.current_b(operation)),
            Some(ChipProgram::N51(n51)) => n51.with_current(|| self.current_b(operation)),
            None => self.current_b(operation),
        }
    }
    fn current_b<T>(
        &mut self,
        operation: impl FnOnce(&mut NativeIo) -> Result<T, power::Error>,
    ) -> Result<T, power::Error> {
        if let Some(full) = self.full.as_ref() {
            full.with_current(|| operation(self.io))
        } else if let Some(basic) = self.basic {
            basic.with_current(|| operation(self.io))
        } else {
            operation(self.io)
        }
    }
}
impl power::Io for Port<'_> {
    fn read8(&mut self, a: u32) -> Result<u8, power::Error> {
        self.current(|io| io.read8(a))
    }
    fn read16(&mut self, a: u32) -> Result<u16, power::Error> {
        self.current(|io| io.read16(a))
    }
    fn read32(&mut self, a: u32) -> Result<u32, power::Error> {
        self.current(|io| io.read32(a))
    }
    fn write8(&mut self, a: u32, v: u8) -> Result<(), power::Error> {
        self.current(|io| io.write8(a, v))
    }
    fn write16(&mut self, a: u32, v: u16) -> Result<(), power::Error> {
        self.current(|io| io.write16(a, v))
    }
    fn write32(&mut self, a: u32, v: u32) -> Result<(), power::Error> {
        self.current(|io| io.write32(a, v))
    }
    fn now_us(&self) -> u64 {
        self.io.now_us()
    }
    async fn delay_us(&mut self, u: u64) {
        self.io.delay_us(u).await
    }
    async fn read_ecv(&mut self) -> Result<Option<u8>, power::Error> {
        Err(power::Error::Unsupported)
    }
}
impl Native {
    pub(super) fn full_radio_scope(&self) -> Option<Arc<radio_policy::Qualification>> {
        self.full_qualification
            .clone()
            .or_else(|| self.ordinary.as_ref().and_then(|g| g.b().cloned()))
    }
    /// The installed chip full program, if any (A, C or RTL8851B).
    pub(super) fn chip_program(&self) -> Option<ChipProgram> {
        self.qualification_a
            .clone()
            .map(ChipProgram::A)
            .or_else(|| self.qualification_c.clone().map(ChipProgram::C))
            .or_else(|| self.qualification_51.clone().map(ChipProgram::N51))
    }
    pub(super) fn radio_io(&mut self) -> Result<Port<'_>, power::Error> {
        self.register_access()?;
        let full = self.full_radio_scope();
        let chip = self.chip_program();
        Ok(Port::new(
            &mut self.io,
            self.calibration.as_ref(),
            full,
            chip,
        ))
    }
}
impl crate::rtw89::channel_bb::Interface for Native {
    fn admit(&mut self) -> Result<(), crate::rtw89::channel_bb::Error> {
        self.calibration_access()
            .map_err(crate::rtw89::channel_bb::Error::Register)
    }
}

impl crate::rtw89::phy_operating::Interface for Native {
    fn admit(&mut self) -> Result<(), rfk::Error> {
        // B: phy_profile_current unchanged; C: its own identity + V1 receipt.
        self.radio_profile_current().map_err(rfk::Error::Register)?;
        if !self.coex_ready || self.nctl_ready {
            return Err(rfk::Error::Policy);
        }
        self.calibration_access().map_err(rfk::Error::Register)
    }
    async fn xtal_read(&mut self, address: u8) -> Result<u8, rfk::Error> {
        crate::rtw89::phy_operating::Interface::admit(self)?;
        // SAFETY: same serialized real factory-qualified startup controller;
        // Native Io encloses every actual transaction in signed/device scopes.
        unsafe { crate::rtw89::radio_shutdown::xtal_read(self, address).await }.map_err(Into::into)
    }
    async fn xtal_write(&mut self, address: u8, value: u8, mask: u8) -> Result<(), rfk::Error> {
        crate::rtw89::phy_operating::Interface::admit(self)?;
        // SAFETY: same exact initial owner; no competing power/XTAL producer.
        unsafe { crate::rtw89::radio_shutdown::xtal_write(self, address, value, mask).await }
            .map_err(Into::into)
    }
}

/// RTL8852C chip dispatch of the post-table radio owner (`radio_c`). The B
/// byte streams above are untouched; this is the C composition with the
/// same retained-owner structure and the same fail-closed admission.
impl Native {
    /// Pure staging of the RTL8852C signed records (no register access):
    /// the C cold calibration record (`N5CB` v1), the base full program
    /// (`N5CB` v2, channel 1/20MHz) and every provisioned noninitial
    /// `N5CC` record over `radio_policy_c::noninitial`, then every
    /// provisioned 6GHz `N5CC` record (`noninitial_6ghz` x
    /// `POWER_TYPES_6GHZ` under the host country). A profile whose
    /// `radio_power_c` plan cannot be built from the actual assets is not
    /// looked up (it stays unadmitted). A missing base or calibration record
    /// is an error before Startup creates its terminal Attempt (retryable).
    pub(in crate::rtw89) fn preflight_radio_c(
        &self,
        assets: &radio_assets::Assets,
    ) -> Result<RadioPreflightC, power::Error> {
        crate::rtw88::pci_park::invoke(&self.authority, || {
            if self.state != State::Active
                || self.chip != ChipId::Rtl8852C
                || self.receive.state() != crate::rtw89::rx_dma::State::Polling
                || self.calibration.is_some()
                || self.qualification_c.is_some()
            {
                return Err(power::Error::Terminal);
            }
            self.radio_profile_current()?;
            let factory = self.factory.as_ref().ok_or(power::Error::Unsupported)?;
            let identity = factory.identity().ok_or(power::Error::Unsupported)?;
            let rfe = identity.calibration().rfe_type;
            let phycap = self.firmware_phycap().ok_or(power::Error::Unsupported)?;
            let cal_board =
                crate::rtw89::calibration_policy::Board::new_c(factory, self.device.id, assets)
                    .map_err(denied)?;
            let calibration =
                crate::rtw89::calibration_policy::Calibration::load(cal_board).map_err(denied)?;
            calibration.current().map_err(denied)?;
            let board = |plan: &radio_power_c::Plan| {
                radio_policy_c::Board::new(
                    self.lifecycle,
                    factory,
                    self.device.id,
                    assets,
                    plan,
                    phycap,
                )
                .map_err(denied)
            };
            let initial = radio_power_c::Plan::from_assets(
                assets,
                rfe,
                operating_channel_c::Profile::INITIAL,
            )
            .map_err(denied)?;
            let mut qualification =
                radio_policy_c::Qualification::load(board(&initial)?).map_err(denied)?;
            for profile in radio_policy_c::noninitial() {
                let Ok(plan) = radio_power_c::Plan::from_assets(assets, rfe, profile) else {
                    continue;
                };
                qualification.load_channel(board(&plan)?).map_err(denied)?;
            }
            // 6GHz `N5CC` records, staged lazily by name: regd.c
            // `rtw89_regd_get`/`rtw89_reg_6ghz_power_recalc` for the host
            // regulatory country and each client power type
            // (`SixGhzPower::new`; a blocked/not-applicable context stages
            // nothing), then only a provisioned record name
            // (`has_channel_6ghz`) costs a 6GHz plan and identity. No host
            // policy snapshot: no 6GHz record is staged (unadmitted).
            if let Ok(policy) = narf_wireless::reg::db::ensure_snapshot() {
                for power in radio_policy_c::POWER_TYPES_6GHZ {
                    let Ok(six) = radio_power_c::SixGhzPower::new(
                        assets.elements(),
                        policy.country_code,
                        Some(power),
                    ) else {
                        continue;
                    };
                    for profile in radio_policy_c::noninitial_6ghz() {
                        if !qualification
                            .has_channel_6ghz(profile, six)
                            .map_err(denied)?
                        {
                            continue;
                        }
                        // The staged identity is TPE-free (`Plan::bind`).
                        let Ok(plan) =
                            radio_power_c::Plan::from_assets_6ghz(assets, rfe, profile, six, None)
                        else {
                            continue;
                        };
                        qualification
                            .load_channel_6ghz(board(&plan)?)
                            .map_err(denied)?;
                    }
                }
            }
            qualification.current().map_err(denied)?;
            Ok(RadioPreflightC {
                cal_board,
                calibration,
                qualification: Arc::new(qualification),
            })
        })
        .map_err(denied)?
    }
    /// The C counterpart of `prepare_basic_rfk` + `prepare_full_radio` for
    /// the initial primary: `radio_c::Radio::prepare_controls` (bb_sethw,
    /// phy.c DM sub-inits via `phy_operating::Operating::prepare_c`, NCTL),
    /// then `radio_c::Radio::prepare` (`rtw8852c_rfk_init`,
    /// set_txpwr_ctrl, power trim, cfg_txrx_path, `__rtw89_set_channel`,
    /// `rtw8852c_rfk_channel`) and the `RF_GET_MCCCH` V0 H2C (category 2,
    /// class 0x0a, function 2, 24-byte body; fw.c `RFK_NTFY_MCC_V0`).
    ///
    /// Admission is the C signed record family staged by
    /// [`Self::preflight_radio_c`], rebound here to this exact Native and
    /// assets: the C cold calibration record (`N5CB` v1) and the C full
    /// program whose base (`N5CB` v2) or `N5CC` record admits exactly
    /// `profile` under the current host rule; that profile is selected
    /// before the first write and every access then runs inside both
    /// capability invocations (`Port`, `calibration_access`). The C
    /// WLAN-only coexistence owner (`coex_native::Coex::prepare_c`) then
    /// runs at core.c's `rtw89_btc_ntfy_init` point, before the DM init.
    /// On `Ready` the C ordinary grant (`OrdinaryGrant::C`, the same
    /// retained signed program) is installed; it carries no B companion
    /// program (WMM/QoS/RA/HT/HE/A-MPDU/sleep/fragments), so every B-only
    /// program accessor reports "no program" on C.
    ///
    /// # Safety
    /// Same retained Startup owner after C `prepare_radio_tables`; the outer
    /// Attempt terminalizes this Native and retains DMA on failure/cancel.
    pub(in crate::rtw89) async unsafe fn prepare_radio_c(
        &mut self,
        owner: &mut radio_c::Radio,
        tables: &radio_init::Init,
        assets: &radio_assets::Assets,
        coex: &mut crate::rtw89::coex_native::Coex,
        profile: operating_channel_c::Profile,
        preflight: RadioPreflightC,
    ) -> Result<(), power::Error> {
        if self.state != State::Active
            || self.chip != ChipId::Rtl8852C
            || owner.state() != radio_c::State::New
            || self.ordinary.is_some()
            || self.full_qualification.is_some()
            || self.qualification_c.is_some()
            || self.calibration.is_some()
            || self.nctl_ready
            || tables.state() != radio_init::State::TablesLoaded
        {
            return Err(power::Error::Terminal);
        }
        self.radio_profile_current()?;
        let factory = self.factory.as_ref().ok_or(power::Error::Unsupported)?;
        let rfe = factory
            .identity()
            .ok_or(power::Error::Unsupported)?
            .calibration()
            .rfe_type;
        let plan = radio_power_c::Plan::from_assets(assets, rfe, profile).map_err(denied)?;
        let cal_board =
            crate::rtw89::calibration_policy::Board::new_c(factory, self.device.id, assets)
                .map_err(denied)?;
        let board = radio_policy_c::Board::new(
            self.lifecycle,
            factory,
            self.device.id,
            assets,
            &plan,
            self.firmware_phycap().ok_or(power::Error::Unsupported)?,
        )
        .map_err(denied)?;
        let RadioPreflightC {
            cal_board: staged,
            calibration: signed,
            qualification,
        } = preflight;
        if staged != cal_board
            || !signed.matches(cal_board)
            || !qualification.channel_matches(board)
            || !qualification.channel_allowed(profile).map_err(denied)?
        {
            return Err(power::Error::Access);
        }
        signed.current().map_err(denied)?;
        qualification.select(profile).map_err(denied)?;
        self.calibration = Some(signed);
        self.qualification_c = Some(qualification);
        if self.coex_ready || coex.state() != crate::rtw89::coex_native::State::New {
            return Err(power::Error::Terminal);
        }
        let protocol = crate::rtw89::coex_native::ProtocolC::for_version(assets.firmware_version())
            .ok_or(power::Error::Unsupported)?;
        self.radio_access()?;
        let cut = self
            .factory
            .as_ref()
            .and_then(|factory| factory.identity())
            .ok_or(power::Error::Unsupported)?
            .cut();
        // core.c rtw89_core_start: rtw89_btc_ntfy_init precedes
        // rtw89_phy_dm_init. SAFETY: current signed C records installed
        // above; same retained owner, CMAC TX closed, no BT/PTA producer.
        unsafe { coex.prepare_c(self, rfe, cut, protocol) }
            .await
            .map_err(|_| power::Error::Access)?;
        self.coex_ready = true;
        let factory = self.factory.as_ref().ok_or(power::Error::Unsupported)?;
        let identity = factory.identity().ok_or(power::Error::Unsupported)?;
        let calibration = *tables.calibration_c().ok_or(power::Error::Unsupported)?;
        if identity.chip() != ChipId::Rtl8852C
            || crate::rtw89::factory_c::Calibration::from_factory(factory) != Some(calibration)
        {
            return Err(power::Error::Access);
        }
        let rfe = identity.calibration().rfe_type;
        let cut = identity.cut();
        let gain = tables.gain().ok_or(power::Error::Unsupported)?.clone();
        let tracking = rfk::c_tssi::Tracking::from_assets(assets).map_err(denied)?;
        let nctl = crate::rtw89::radio_table::program(
            assets.table(4).ok_or(power::Error::Unsupported)?,
            rfe,
            cut,
        )
        .map_err(denied)?;
        let rx_nss = self
            .firmware_phycap()
            .ok_or(power::Error::Unsupported)?
            .rx_nss();
        self.radio_started = true;
        // SAFETY: caller contract; admission rechecked by every Port access.
        let mut operating = self.operating.take().ok_or(power::Error::Terminal)?;
        // SAFETY: caller contract; the C DM sub-inits run between bb_sethw
        // and NCTL with phy_operating::Interface admission on every access.
        let result = unsafe { owner.prepare_controls(self, &mut operating, identity, &nctl) }.await;
        self.operating = Some(operating);
        result.map_err(radio_c::error)?;
        self.nctl_ready = true;
        // SAFETY: same owner after bb_sethw/NCTL; rfk::Interface admits
        // every access against the retained envelope.
        let mcc = unsafe {
            owner.prepare(
                self,
                radio_c::Inputs {
                    gain: &gain,
                    calibration: &calibration,
                    power: &plan,
                    tracking: &tracking,
                    cut,
                    rx_nss,
                },
            )
        }
        .await
        .map_err(radio_c::error)?;
        self.runtime_command(2, 0x0a, 2, &mcc, false, super::station::Permit::Legacy)
            .await?;
        if owner.state() != radio_c::State::Ready {
            return Err(power::Error::Terminal);
        }
        // The C ordinary grant: the same signed program that admitted the
        // whole RFK/channel recipe, rechecked now, opens ordinary TX/ACK
        // (core.c rtw89_core_start ends with the radio Ready for mac80211).
        let qualification = self.qualification_c.clone().ok_or(power::Error::Access)?;
        qualification.current().map_err(denied)?;
        if qualification.active() != profile {
            return Err(power::Error::Access);
        }
        self.channel = Some((
            OperatingChannel::new(profile.band(), profile.primary()),
            owner.epoch(),
        ));
        self.ordinary = Some(OrdinaryGrant::C(qualification));
        Ok(())
    }
}
impl Native {
    /// RTL8852C counterpart of [`Self::retune_full_radio`] for one typed
    /// `profile` (2.4GHz 20MHz/HT40, 5GHz 20/40/80/160MHz, or with `six`
    /// a 6GHz 20/40/80/160MHz profile under its regd.c power context and
    /// TPE constraint) on the Ready C radio: drain, withhold the C ordinary grant, `select` the profile's
    /// signed `N5CB`/`N5CC` envelope, `radio_c::Radio::retune` (core.c
    /// `rtw89_set_channel` -> rtw8852c.c `rtw8852c_set_channel`, then
    /// `rtw89_chip_rfk_channel` -> `rtw8852c_rfk_channel`), the
    /// `RF_GET_MCCCH` V0 H2C (fw.c `rtw89_fw_h2c_rf_ntfy_mcc`,
    /// `RFK_NTFY_MCC_V0`), then reinstall the same grant.
    ///
    /// Admission mirrors `prepare_radio_c`: the identity is rebound to this
    /// exact factory/assets/plan (`radio_policy_c::Board::new` +
    /// `channel_matches`) and the profile must be `channel_allowed` under
    /// the current host rule. Refused with nothing withheld (retryable)
    /// unless ordinary TX, the H2C queue and RX backlog are drained, the
    /// radio is awake and no monitor or sleep owner exists; `linked` is the
    /// associated-station channel switch (a peer must exist; otherwise none
    /// may).
    ///
    /// # Safety
    /// Same retained Startup owner/tables/assets that prepared `owner`. A
    /// failed or dropped future after the grant is withheld leaves the
    /// radio non-Ready; the caller's Attempt terminalizes this Native.
    pub(in crate::rtw89) async unsafe fn retune_radio_c(
        &mut self,
        owner: &mut radio_c::Radio,
        tables: &radio_init::Init,
        assets: &radio_assets::Assets,
        profile: operating_channel_c::Profile,
        six: Option<(radio_power_c::SixGhzPower, Option<i8>)>,
        linked: bool,
    ) -> Result<u32, power::Error> {
        if self.chip != ChipId::Rtl8852C {
            return Err(power::Error::Unsupported);
        }
        self.radio_profile_current()?;
        self.ordinary_current()?;
        if owner.state() != radio_c::State::Ready
            || self.full_qualification.is_some()
            || !self.coex_ready
            || !self.nctl_ready
        {
            return Err(power::Error::Terminal);
        }
        let context = six.map(|(power, _)| power);
        let admissible = match context {
            None => radio_policy_c::admissible(profile),
            Some(_) => radio_policy_c::admissible_6ghz(profile),
        };
        if !admissible {
            return Err(power::Error::Unsupported);
        }
        // A 6GHz program is rebuilt even on the same profile: its regd.c
        // context or TPE constraint may have changed
        // (`rtw89_reg_6ghz_recalc` -> `rtw89_core_set_chip_txpwr`).
        if context.is_none() && owner.channel() == Some(profile) {
            return Ok(owner.epoch());
        }
        let qualification = self.qualification_c.clone().ok_or(power::Error::Terminal)?;
        if !self.ordinary.as_ref().is_some_and(
            |grant| matches!(grant, OrdinaryGrant::C(q) if Arc::ptr_eq(q, &qualification)),
        ) {
            return Err(power::Error::Terminal);
        }
        let allowed = match context {
            None => qualification.channel_allowed(profile),
            Some(power) => qualification.channel_allowed_6ghz(profile, power),
        };
        if !allowed.map_err(denied)? {
            return Err(power::Error::Unsupported);
        }
        let factory = self.factory.as_ref().ok_or(power::Error::Unsupported)?;
        let identity = factory.identity().ok_or(power::Error::Unsupported)?;
        if identity.chip() != ChipId::Rtl8852C {
            return Err(power::Error::Access);
        }
        let rfe = identity.calibration().rfe_type;
        let cut = identity.cut();
        // 6GHz: `rtw8852c_set_txpwr` under the regd.c context and the
        // intersected STD TPE (`Plan::from_assets_6ghz`); its identity is
        // the TPE-free staged record's.
        let plan = match six {
            None => radio_power_c::Plan::from_assets(assets, rfe, profile),
            Some((power, tpe)) => {
                radio_power_c::Plan::from_assets_6ghz(assets, rfe, profile, power, tpe)
            }
        }
        .map_err(denied)?;
        let phycap = self.firmware_phycap().ok_or(power::Error::Unsupported)?;
        let rx_nss = phycap.rx_nss();
        let board = radio_policy_c::Board::new(
            self.lifecycle,
            factory,
            self.device.id,
            assets,
            &plan,
            phycap,
        )
        .map_err(denied)?;
        if !qualification.channel_matches(board) {
            return Err(power::Error::Access);
        }
        let calibration = *tables.calibration_c().ok_or(power::Error::Unsupported)?;
        if crate::rtw89::factory_c::Calibration::from_factory(factory) != Some(calibration) {
            return Err(power::Error::Access);
        }
        let gain = tables.gain().ok_or(power::Error::Unsupported)?.clone();
        let tracking = rfk::c_tssi::Tracking::from_assets(assets).map_err(denied)?;
        // Drain: rtw89_ops_flush / ieee80211_offchannel_stop_vifs. Busy is a
        // proven-unpublished refusal; the caller retries after draining.
        self.poll().map_err(|_| power::Error::Access)?;
        if self.sleep_blocked
            || self.sleep_reset.is_some()
            || self.station_runtime.peer.is_some() != linked
            || self.station_runtime.monitor.is_some()
            || self.queue.pending() != 0
            || !self.station_runtime.backlog.is_empty()
            || self
                .station_runtime
                .core
                .as_ref()
                .is_some_and(|core| !core.ready())
        {
            return Err(power::Error::Busy);
        }
        // rtw89_leave_ps_mode precondition: actual CPWM/MACID0 awake.
        crate::rtw89::station_control::awake(&mut self.io)?;
        // Close ordinary publication; RFK and the MCC H2C run inside the
        // retained C program (`Port`/`calibration_access`) whose envelope is
        // now the target profile's signed record over its occupied span.
        let grant = self.ordinary.take().ok_or(power::Error::Terminal)?;
        self.channel = None;
        match context {
            None => qualification.select(profile),
            Some(power) => qualification.select_6ghz(profile, power),
        }
        .map_err(denied)?;
        // SAFETY: caller contract; queues drained and grant withheld above.
        let mcc = unsafe {
            owner.retune(
                self,
                radio_c::Inputs {
                    gain: &gain,
                    calibration: &calibration,
                    power: &plan,
                    tracking: &tracking,
                    cut,
                    rx_nss,
                },
            )
        }
        .await
        .map_err(radio_c::error)?;
        self.runtime_command(2, 0x0a, 2, &mcc, false, super::station::Permit::Legacy)
            .await?;
        self.radio_profile_current()?;
        if owner.state() != radio_c::State::Ready
            || owner.channel() != Some(profile)
            || qualification.active() != profile
            || qualification.active_six_ghz() != context
        {
            return Err(power::Error::Terminal);
        }
        qualification.current().map_err(denied)?;
        self.channel = Some((
            OperatingChannel::new(profile.band(), profile.primary()),
            owner.epoch(),
        ));
        // RX admission follows the programmed width (as the B retune): up to
        // this channel's bandwidth (C: 160MHz = RTW89_CHANNEL_WIDTH_160 only
        // when programmed at 160), VHT rates only on a 5GHz wide channel.
        if let Some(core) = self.station_runtime.core.as_mut() {
            let width = profile.width() as u8;
            core.set_operating_width(
                width,
                width != 0 && profile.band() == operating_channel_c::Band::Ghz5,
            );
        }
        // ieee80211_offchannel_return: queues reopen only on the same grant.
        self.ordinary = Some(grant);
        Ok(owner.epoch())
    }
}
/// Pure staged RTL8852C signed records (`Native::preflight_radio_c`).
pub(in crate::rtw89) struct RadioPreflightC {
    cal_board: crate::rtw89::calibration_policy::Board,
    calibration: crate::rtw89::calibration_policy::Calibration,
    qualification: Arc<radio_policy_c::Qualification>,
}
impl Native {
    /// Chip dispatch of `phy_profile_current`: B unchanged; C requires the
    /// actual C factory identity and the same firmware PHY-capability
    /// receipt topology (two-stream RX-AB; RTL8852C `rx_nss` = 2).
    pub(super) fn radio_profile_current(&self) -> Result<(), power::Error> {
        if self.chip == ChipId::Rtl8851B {
            return self.radio_profile_current_51();
        }
        if self.chip == ChipId::Rtl8852A {
            return self.radio_profile_current_a();
        }
        if self.chip != ChipId::Rtl8852C {
            return self.phy_profile_current();
        }
        crate::rtw88::pci_park::invoke(&self.authority, || {
            if self.state != State::Active
                || self
                    .factory
                    .as_ref()
                    .and_then(|factory| factory.identity())
                    .is_none_or(|identity| identity.chip() != ChipId::Rtl8852C)
            {
                return Err(power::Error::Terminal);
            }
            let phycap = self.phycap.as_ref().ok_or(power::Error::Unsupported)?;
            // Only a receipt earned through the V1 (0x7140) block binds C.
            if !phycap.is_c() {
                return Err(power::Error::Access);
            }
            phycap.initial_profile()
        })
        .map_err(|_| power::Error::Access)?
    }
    /// RTL8852A: the actual RTL8852A identity and an RTL8852A-decoded
    /// firmware receipt (2T2R TX-A RX-AB, `Receipt::initial_profile`).
    fn radio_profile_current_a(&self) -> Result<(), power::Error> {
        crate::rtw88::pci_park::invoke(&self.authority, || {
            if self.state != State::Active
                || self
                    .factory
                    .as_ref()
                    .and_then(|factory| factory.identity())
                    .is_none_or(|identity| identity.chip() != ChipId::Rtl8852A)
            {
                return Err(power::Error::Terminal);
            }
            let phycap = self.phycap.as_ref().ok_or(power::Error::Unsupported)?;
            // Only a receipt earned through the B (0x8140) block and
            // decoded as A binds A.
            if !phycap.is_a() {
                return Err(power::Error::Access);
            }
            phycap.initial_profile()
        })
        .map_err(|_| power::Error::Access)?
    }
    /// RTL8851B: the actual RTL8851B identity and an RTL8851B-decoded
    /// firmware receipt (1T1R RF_A, `Receipt::initial_profile_51`).
    fn radio_profile_current_51(&self) -> Result<(), power::Error> {
        crate::rtw88::pci_park::invoke(&self.authority, || {
            if self.state != State::Active
                || self
                    .factory
                    .as_ref()
                    .and_then(|factory| factory.identity())
                    .is_none_or(|identity| identity.chip() != ChipId::Rtl8851B)
            {
                return Err(power::Error::Terminal);
            }
            self.phycap
                .as_ref()
                .ok_or(power::Error::Unsupported)?
                .initial_profile_51()
        })
        .map_err(|_| power::Error::Access)?
    }
}
