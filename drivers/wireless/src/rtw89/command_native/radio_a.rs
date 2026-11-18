// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! RTL8852A chip dispatch of the post-table radio owner (`radio_a`), the
//! RTL8852C composition (`radio.rs` `prepare_radio_c`) over the RTL8852A
//! signed record family (`N5AB` v1 calibration, `N5AB` v2 base, `N5AC`
//! per-channel, `N5AF` fragment companion) and the RTL8852A WLAN-only
//! coexistence owner. The B, C and RTL8851B byte streams are untouched.
use super::*;
use crate::rtw89::{
    calibration_policy, coex_native, factory_a, operating_channel::Profile, power, radio_a,
    radio_assets, radio_init, radio_policy_a, radio_power_c,
};
use alloc::sync::Arc;

fn denied(_: impl core::fmt::Debug) -> power::Error {
    power::Error::Access
}

/// Pure RTL8852A record staging consumed by one [`Native::prepare_radio_a`].
pub(in crate::rtw89) struct RadioPreflightA {
    cal_board: calibration_policy::Board,
    calibration: calibration_policy::Calibration,
    qualification: Arc<radio_policy_a::Qualification>,
}

impl Native {
    /// Pure staging of the RTL8852A signed records (no register access):
    /// the cold calibration record (`N5AB` v1), the base full program
    /// (`N5AB` v2, channel 1/20MHz) and every provisioned `N5AC` record
    /// over `radio_policy_a::noninitial`. A profile whose
    /// `radio_power_c::Plan::from_elements_a` plan cannot be built from
    /// the actual assets is not looked up (it stays unadmitted). A missing
    /// base or calibration record is an error before Startup creates its
    /// terminal Attempt (retryable).
    pub(in crate::rtw89) fn preflight_radio_a(
        &self,
        assets: &radio_assets::Assets,
    ) -> Result<RadioPreflightA, power::Error> {
        crate::rtw88::pci_park::invoke(&self.authority, || {
            if self.state != State::Active
                || self.chip != ChipId::Rtl8852A
                || self.mac_a.is_none()
                || self.receive.state() != crate::rtw89::rx_dma::State::Polling
                || self.calibration.is_some()
                || self.qualification_a.is_some()
                || self.qualification_c.is_some()
                || self.qualification_51.is_some()
            {
                return Err(power::Error::Terminal);
            }
            self.radio_profile_current()?;
            self.mac_a
                .as_ref()
                .ok_or(power::Error::Terminal)?
                .current()?;
            let factory = self.factory.as_ref().ok_or(power::Error::Unsupported)?;
            let rfe = factory
                .identity()
                .ok_or(power::Error::Unsupported)?
                .calibration()
                .rfe_type;
            let phycap = self.firmware_phycap().ok_or(power::Error::Unsupported)?;
            let cal_board = calibration_policy::Board::new_a(factory, self.device.id, assets)
                .map_err(denied)?;
            let calibration = calibration_policy::Calibration::load(cal_board).map_err(denied)?;
            calibration.current().map_err(denied)?;
            let board = |profile: Profile, plan: &radio_power_c::Plan| {
                radio_policy_a::Board::new(
                    self.lifecycle,
                    factory,
                    self.device.id,
                    assets,
                    profile,
                    plan,
                    phycap,
                )
                .map_err(denied)
            };
            let elements = assets.elements();
            let initial = radio_power_c::Plan::from_elements_a(elements, rfe, Profile::INITIAL)
                .map_err(denied)?;
            let mut qualification =
                radio_policy_a::Qualification::load(board(Profile::INITIAL, &initial)?)
                    .map_err(denied)?;
            for profile in radio_policy_a::noninitial() {
                let Ok(plan) = radio_power_c::Plan::from_elements_a(elements, rfe, profile) else {
                    continue;
                };
                qualification
                    .load_channel(board(profile, &plan)?)
                    .map_err(denied)?;
            }
            qualification.current().map_err(denied)?;
            Ok(RadioPreflightA {
                cal_board,
                calibration,
                qualification: Arc::new(qualification),
            })
        })
        .map_err(denied)?
    }

    /// The RTL8852A counterpart of `prepare_radio_c` for the initial
    /// primary: `radio_a::Radio::prepare_controls` (`rtw8852a_bb_sethw`,
    /// phy.c DM sub-inits, NCTL), then `radio_a::Radio::prepare`
    /// (`rtw8852a_rfk_init`, set_txpwr_ctrl, power trim; no
    /// `bb_cfg_txrx_path`, no channel program, no RF_GET_MCCCH).
    ///
    /// Admission is the RTL8852A signed record family staged by
    /// [`Self::preflight_radio_a`], rebound here to this exact Native and
    /// assets: the cold calibration record (`N5AB` v1) and the full program
    /// whose base (`N5AB` v2) or `N5AC` record admits exactly `profile`
    /// under the current host rule. That profile is selected before the
    /// first write and every access then runs inside both capability
    /// invocations (`Port`, `calibration_access`). The RTL8852A WLAN-only
    /// coexistence owner (`coex_native::Coex::prepare_a`) runs at core.c's
    /// `rtw89_btc_ntfy_init` point, before the DM init. On `Ready` the
    /// RTL8852A ordinary grant (`OrdinaryGrant::A`, the same retained
    /// signed program, rechecked) is installed; it carries no B companion
    /// program, so every B-only program accessor reports "no program".
    /// The A channel-control and exact `set_txpwr` prefix run next, inside
    /// their scheduler/help window. Programmed is distinct from complete
    /// channel RFK. Actual live non-TSSI observations, source TSSI high-power/
    /// pre-TX and complete channel RFK run before channel publication. The
    /// outer original Attempt closes A autonomous engines on failure/drop.
    ///
    /// # Safety
    /// Same retained Startup owner after RTL8852A `prepare_radio_tables`;
    /// the outer Attempt terminalizes this Native and retains DMA on
    /// failure/cancel.
    pub(in crate::rtw89) async unsafe fn prepare_radio_a(
        &mut self,
        owner: &mut radio_a::Radio,
        tables: &radio_init::Init,
        assets: &radio_assets::Assets,
        coex: &mut coex_native::Coex,
        profile: Profile,
        preflight: RadioPreflightA,
    ) -> Result<(), power::Error> {
        if self.state != State::Active
            || self.chip != ChipId::Rtl8852A
            || self.mac_a.is_none()
            || owner.state() != radio_a::State::New
            || self.ordinary.is_some()
            || self.full_qualification.is_some()
            || self.qualification_a.is_some()
            || self.qualification_c.is_some()
            || self.qualification_51.is_some()
            || self.calibration.is_some()
            || self.nctl_ready
            || tables.state() != radio_init::State::TablesLoaded
        {
            return Err(power::Error::Terminal);
        }
        self.radio_profile_current()?;
        let mac_board = crate::rtw89::mac_a_policy::Board::new(
            self.lifecycle,
            self.factory.as_ref().ok_or(power::Error::Unsupported)?,
            self.device.id,
            assets,
        )
        .map_err(denied)?;
        let mac_grant = self.mac_a.as_ref().ok_or(power::Error::Terminal)?;
        if !mac_grant.matches(mac_board) {
            return Err(power::Error::Access);
        }
        mac_grant.current()?;
        let factory = self.factory.as_ref().ok_or(power::Error::Unsupported)?;
        let rfe = factory
            .identity()
            .ok_or(power::Error::Unsupported)?
            .calibration()
            .rfe_type;
        let plan = radio_power_c::Plan::from_elements_a(assets.elements(), rfe, profile)
            .map_err(denied)?;
        let tracking = crate::rtw89::rfk::a_tssi::Tracking::from_assets(assets).map_err(denied)?;
        let tail =
            crate::rtw89::rfk::a_tssi::tail::Inputs::from_assets(assets, rfe, plan.channel())
                .map_err(denied)?;
        let cal_board =
            calibration_policy::Board::new_a(factory, self.device.id, assets).map_err(denied)?;
        let board = radio_policy_a::Board::new(
            self.lifecycle,
            factory,
            self.device.id,
            assets,
            profile,
            &plan,
            self.firmware_phycap().ok_or(power::Error::Unsupported)?,
        )
        .map_err(denied)?;
        let RadioPreflightA {
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
        self.qualification_a = Some(qualification);
        if self.coex_ready || coex.state() != coex_native::State::New {
            return Err(power::Error::Terminal);
        }
        let protocol = coex_native::ProtocolA::for_version(assets.firmware_version())
            .ok_or(power::Error::Unsupported)?;
        self.radio_access()?;
        let cut = self
            .factory
            .as_ref()
            .and_then(|factory| factory.identity())
            .ok_or(power::Error::Unsupported)?
            .cut();
        self.calibration_access()?;
        // core.c rtw89_core_start: rtw89_btc_ntfy_init precedes
        // rtw89_phy_dm_init. SAFETY: current signed RTL8852A records
        // installed above; same retained owner, CMAC TX closed, no BT/PTA
        // producer. No XTAL/ACV read: `rtw8852a_btc_set_rfe` never assigns
        // `kt_ver_adie` (only 8851B/8852BT/8922A/8922D do), so the init
        // encoding carries 0 there.
        unsafe { coex.prepare_a(self, rfe, cut, protocol) }
            .await
            .map_err(|_| power::Error::Access)?;
        self.coex_ready = true;
        let factory = self.factory.as_ref().ok_or(power::Error::Unsupported)?;
        let identity = factory.identity().ok_or(power::Error::Unsupported)?;
        let calibration = *tables.calibration_a().ok_or(power::Error::Unsupported)?;
        if identity.chip() != ChipId::Rtl8852A
            || factory_a::Calibration::from_factory(factory) != Some(calibration)
        {
            return Err(power::Error::Access);
        }
        let rfe = identity.calibration().rfe_type;
        let cut = identity.cut();
        let nctl = crate::rtw89::radio_table::program(
            assets.table(4).ok_or(power::Error::Unsupported)?,
            rfe,
            cut,
        )
        .map_err(denied)?;
        self.radio_started = true;
        let mut operating = self.operating.take().ok_or(power::Error::Terminal)?;
        // SAFETY: caller contract; the DM sub-inits run between bb_sethw and
        // NCTL with phy_operating::Interface admission on every access.
        let result = unsafe { owner.prepare_controls(self, &mut operating, identity, &nctl) }.await;
        self.operating = Some(operating);
        result.map_err(crate::rtw89::radio_c::error)?;
        self.nctl_ready = true;
        // SAFETY: same owner after bb_sethw/NCTL; rfk::Interface admits
        // every access against the retained envelope.
        unsafe {
            owner.prepare(
                self,
                radio_a::Inputs {
                    calibration: &calibration,
                },
            )
        }
        .await
        .map_err(crate::rtw89::radio_c::error)?;
        // SAFETY: the selected signed A profile/plan and retained init
        // above are current; no ordinary station or response producer.
        unsafe { owner.program_channel(self, profile, &plan) }
            .await
            .map_err(crate::rtw89::radio_c::error)?;
        // SAFETY: same retained current measured A owner after its actual
        // source channel and live observations; original Attempt owns A
        // restrictive terminal PMAC/BB closure on failure or cancellation.
        unsafe {
            owner.complete_channel(
                self,
                radio_a::ChannelInputs {
                    calibration: &calibration,
                    tracking: &tracking,
                    tail,
                },
            )
        }
        .await
        .map_err(crate::rtw89::radio_c::error)?;
        if owner.state() != radio_a::State::Ready
            || owner.programmed_channel() != Some(profile)
            || owner.channel() != Some(profile)
            || owner.observations().is_none()
            || owner.fem()
                != self
                    .factory
                    .as_ref()
                    .and_then(|factory| factory.identity())
                    .and_then(factory_a::Fem::from_identity)
        {
            return Err(power::Error::Terminal);
        }
        let qualification = self.qualification_a.clone().ok_or(power::Error::Access)?;
        qualification.current().map_err(denied)?;
        if qualification.active() != profile {
            return Err(power::Error::Access);
        }
        // Only the complete actual source RFK/PMAC receipt above permits
        // channel publication. Missing thermal/tail/DPK evidence fails closed.
        self.channel = Some((
            OperatingChannel::new(plan.channel().band(), profile.primary()),
            owner.epoch(),
        ));
        self.ordinary = Some(OrdinaryGrant::A(qualification));
        Ok(())
    }
}

impl Native {
    pub(super) fn a_ordinary(&self) -> Result<bool, power::Error> {
        if self.chip != ChipId::Rtl8852A {
            return Ok(false);
        }
        crate::rtw88::pci_park::invoke(&self.authority, || {
            self.ordinary_current()?;
            let q = self
                .qualification_a
                .as_ref()
                .ok_or(power::Error::Terminal)?;
            if !self.ordinary.as_ref().is_some_and(
                |grant| matches!(grant, OrdinaryGrant::A(original) if Arc::ptr_eq(original,q)),
            ) {
                return Err(power::Error::Terminal);
            }
            q.current().map_err(denied)?;
            Ok(true)
        })
        .map_err(denied)?
    }
    pub(super) fn a_program(
        &self,
        program: crate::rtw89::radio_policy::Program,
    ) -> Result<bool, power::Error> {
        if !self.a_ordinary()? {
            return Err(power::Error::Unsupported);
        }
        self.qualification_a
            .as_ref()
            .ok_or(power::Error::Terminal)?
            .allows(program)
            .map_err(denied)
    }
    pub(super) fn a_admitted_channels(&self) -> Result<u64, power::Error> {
        if !self.a_ordinary()? {
            return Err(power::Error::Unsupported);
        }
        let q = self
            .qualification_a
            .as_ref()
            .ok_or(power::Error::Terminal)?;
        let mut mask = 0;
        for primary in (1..=13).chain(crate::rtw89::operating_channel::GHZ5) {
            let profile = Profile::from_primary(primary).ok_or(power::Error::Unsupported)?;
            if q.channel_active(profile).map_err(denied)? {
                mask |= 1u64
                    << crate::rtw89::operating_channel::slot(primary)
                        .ok_or(power::Error::Unsupported)?;
            }
        }
        Ok(mask)
    }
    pub(super) fn a_admitted_wide(&self) -> Result<alloc::vec::Vec<Profile>, power::Error> {
        if !self.a_ordinary()? {
            return Err(power::Error::Unsupported);
        }
        let q = self
            .qualification_a
            .as_ref()
            .ok_or(power::Error::Terminal)?;
        let mut profiles = alloc::vec::Vec::new();
        for profile in crate::rtw89::command_native::radio::wide_profiles() {
            if q.channel_active(profile).map_err(denied)? {
                profiles.push(profile);
            }
        }
        Ok(profiles)
    }
    /// # Safety
    /// Original Startup A radio/tables/assets, no competing reset/IRQ/PHY/PM
    /// producer. The enclosing retained Attempt terminalizes after any grant
    /// withdrawal, access failure or dropped future. No replacement owner.
    pub(in crate::rtw89) async unsafe fn retune_radio_a(
        &mut self,
        owner: &mut radio_a::Radio,
        tables: &radio_init::Init,
        assets: &radio_assets::Assets,
        profile: Profile,
        linked: bool,
    ) -> Result<u32, power::Error> {
        if self.chip != ChipId::Rtl8852A {
            return Err(power::Error::Unsupported);
        }
        self.radio_profile_current()?;
        if !self.a_ordinary()?
            || owner.state() != radio_a::State::Ready
            || !self.coex_ready
            || !self.nctl_ready
            || self.full_qualification.is_some()
        {
            return Err(power::Error::Terminal);
        }
        if !radio_policy_a::admissible(profile) {
            return Err(power::Error::Unsupported);
        }
        let q = self.qualification_a.clone().ok_or(power::Error::Terminal)?;
        if owner.channel() == Some(profile) {
            if q.active() != profile
                || self.operating_channel()
                    != Some((OperatingChannel::legacy(profile.primary()), owner.epoch()))
            {
                return Err(power::Error::Terminal);
            }
            return Ok(owner.epoch());
        }
        // A live station needs an actual RXQ/RPQ epoch/quarantine handoff,
        // not only software backlog and Core readiness. That continuation
        // is not composed; refuse before withdrawing any source authority.
        if self.station_runtime.started() {
            return Err(power::Error::Unsupported);
        }
        if !q.channel_allowed(profile).map_err(denied)? {
            return Err(power::Error::Unsupported);
        }
        let factory = self.factory.as_ref().ok_or(power::Error::Unsupported)?;
        let identity = factory.identity().ok_or(power::Error::Unsupported)?;
        let rfe = identity.calibration().rfe_type;
        let plan = radio_power_c::Plan::from_elements_a(assets.elements(), rfe, profile)
            .map_err(denied)?;
        let board = radio_policy_a::Board::new(
            self.lifecycle,
            factory,
            self.device.id,
            assets,
            profile,
            &plan,
            self.firmware_phycap().ok_or(power::Error::Unsupported)?,
        )
        .map_err(denied)?;
        if !q.channel_matches(board) {
            return Err(power::Error::Access);
        }
        let calibration = *tables.calibration_a().ok_or(power::Error::Unsupported)?;
        if factory_a::Calibration::from_factory(factory) != Some(calibration) {
            return Err(power::Error::Access);
        }
        let tracking = crate::rtw89::rfk::a_tssi::Tracking::from_assets(assets).map_err(denied)?;
        let tail =
            crate::rtw89::rfk::a_tssi::tail::Inputs::from_assets(assets, rfe, plan.channel())
                .map_err(denied)?;
        self.poll().map_err(|_| power::Error::Access)?;
        if self.sleep_blocked
            || self.sleep_reset.is_some()
            || self.station_runtime.peer.is_some() != linked
            || self.station_runtime.monitor.is_some()
            || self.station_runtime.ap.is_some()
            || (linked && self.station_runtime.core.is_none())
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
        self.with_ordinary_current(|native| crate::rtw89::station_control::awake(&mut native.io))?;
        let grant = self.ordinary.take().ok_or(power::Error::Terminal)?;
        self.channel = None;
        q.select(profile).map_err(denied)?;
        // SAFETY: this is the same original A Radio/tables/assets, with its
        // exact target qualification selected above before effects. The live
        // packet runtime is refused, actual command/Core/awake checks passed,
        // and ordinary publication is withdrawn. Interface invokes current
        // source/device authority; the enclosing Attempt retains DMA and
        // closes uncertain help/PMAC/scheduler ownership on failure or drop.
        unsafe {
            owner.retune(
                self,
                profile,
                &plan,
                radio_a::ChannelInputs {
                    calibration: &calibration,
                    tracking: &tracking,
                    tail,
                },
            )
        }
        .await
        .map_err(crate::rtw89::radio_c::error)?;
        self.radio_profile_current()?;
        q.current().map_err(denied)?;
        if owner.channel() != Some(profile) || q.active() != profile {
            return Err(power::Error::Terminal);
        }
        self.channel = Some((
            OperatingChannel::new(plan.channel().band(), profile.primary()),
            owner.epoch(),
        ));
        if let Some(core) = self.station_runtime.core.as_mut() {
            core.set_operating_width(
                profile.width() as u8,
                profile.width() as u8 != 0 && profile.is_5ghz(),
            );
        }
        self.ordinary = Some(grant);
        Ok(owner.epoch())
    }
}
