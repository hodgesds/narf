// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! RTL8851B chip dispatch of the post-table radio owner (`radio_51`), the
//! RTL8852C composition (`radio.rs` `prepare_radio_c`) over the RTL8851B
//! signed record family (`N51B` v1 calibration, `N51B` v2 base, `N51C`
//! per-channel) and the RTL8851B WLAN-only coexistence owner. The B and C
//! byte streams are untouched.
use super::*;
use crate::rtw89::{
    calibration_policy, coex_native, operating_channel::Profile, power, radio_51, radio_assets,
    radio_init, radio_policy_51, radio_power_c, rfk,
};
use alloc::sync::Arc;

fn denied(_: impl core::fmt::Debug) -> power::Error {
    power::Error::Access
}

/// XTAL_SI_CV (mac.h) and `XTAL_SI_ACV_MASK` GENMASK(3, 0).
const XTAL_SI_CV: u8 = 0x41;

/// Pure RTL8851B record staging consumed by one [`Native::prepare_radio_51`].
pub(in crate::rtw89) struct RadioPreflight51 {
    cal_board: calibration_policy::Board,
    calibration: calibration_policy::Calibration,
    qualification: Arc<radio_policy_51::Qualification>,
}

impl Native {
    /// Pure staging of the RTL8851B signed records (no register access):
    /// the cold calibration record (`N51B` v1), the base full program
    /// (`N51B` v2, channel 1/20MHz) and every provisioned `N51C` record over
    /// `radio_policy_51::noninitial`. A profile whose
    /// `radio_power_c::Plan::from_elements_51` plan cannot be built from the
    /// actual assets is not looked up (it stays unadmitted). A missing base
    /// or calibration record is an error before Startup creates its terminal
    /// Attempt (retryable).
    pub(in crate::rtw89) fn preflight_radio_51(
        &self,
        assets: &radio_assets::Assets,
    ) -> Result<RadioPreflight51, power::Error> {
        crate::rtw88::pci_park::invoke(&self.authority, || {
            if self.state != State::Active
                || self.chip != ChipId::Rtl8851B
                || self.receive.state() != crate::rtw89::rx_dma::State::Polling
                || self.calibration.is_some()
                || self.qualification_c.is_some()
                || self.qualification_51.is_some()
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
            let phycap = self.firmware_phycap().ok_or(power::Error::Unsupported)?;
            let cal_board = calibration_policy::Board::new_51(factory, self.device.id, assets)
                .map_err(denied)?;
            let calibration = calibration_policy::Calibration::load(cal_board).map_err(denied)?;
            calibration.current().map_err(denied)?;
            let board = |profile: Profile, plan: &radio_power_c::Plan| {
                radio_policy_51::Board::new(
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
            let initial = radio_power_c::Plan::from_elements_51(elements, rfe, Profile::INITIAL)
                .map_err(denied)?;
            let mut qualification =
                radio_policy_51::Qualification::load(board(Profile::INITIAL, &initial)?)
                    .map_err(denied)?;
            for profile in radio_policy_51::noninitial() {
                let Ok(plan) = radio_power_c::Plan::from_elements_51(elements, rfe, profile) else {
                    continue;
                };
                qualification
                    .load_channel(board(profile, &plan)?)
                    .map_err(denied)?;
            }
            qualification.current().map_err(denied)?;
            Ok(RadioPreflight51 {
                cal_board,
                calibration,
                qualification: Arc::new(qualification),
            })
        })
        .map_err(denied)?
    }

    /// The RTL8851B counterpart of `prepare_radio_c` for the initial
    /// primary: `radio_51::Radio::prepare_controls` (`rtw8851b_bb_sethw`,
    /// phy.c DM sub-inits, NCTL), then `radio_51::Radio::prepare`
    /// (`rtw8851b_rfk_init`, set_txpwr_ctrl, power trim, cfg_txrx_path,
    /// `__rtw89_set_channel`, `rtw8851b_rfk_channel`; no RF_GET_MCCCH).
    ///
    /// Admission is the RTL8851B signed record family staged by
    /// [`Self::preflight_radio_51`], rebound here to this exact Native and
    /// assets: the cold calibration record (`N51B` v1) and the full program
    /// whose base (`N51B` v2) or `N51C` record admits exactly `profile`
    /// under the current host rule. That profile is selected before the
    /// first write and every access then runs inside both capability
    /// invocations (`Port`, `calibration_access`). The RTL8851B WLAN-only
    /// coexistence owner (`coex_native::Coex::prepare_51`) runs at core.c's
    /// `rtw89_btc_ntfy_init` point, before the DM init. On `Ready` the
    /// RTL8851B ordinary grant (`OrdinaryGrant::N51`, the same retained
    /// signed program, rechecked) is installed; it carries no B companion
    /// program, so every B-only program accessor reports "no program".
    ///
    /// # Safety
    /// Same retained Startup owner after RTL8851B `prepare_radio_tables`;
    /// the outer Attempt terminalizes this Native and retains DMA on
    /// failure/cancel.
    pub(in crate::rtw89) async unsafe fn prepare_radio_51(
        &mut self,
        owner: &mut radio_51::Radio,
        tables: &radio_init::Init,
        assets: &radio_assets::Assets,
        coex: &mut coex_native::Coex,
        profile: Profile,
        preflight: RadioPreflight51,
    ) -> Result<(), power::Error> {
        if self.state != State::Active
            || self.chip != ChipId::Rtl8851B
            || owner.state() != radio_51::State::New
            || self.ordinary.is_some()
            || self.full_qualification.is_some()
            || self.qualification_c.is_some()
            || self.qualification_51.is_some()
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
        let plan = radio_power_c::Plan::from_elements_51(assets.elements(), rfe, profile)
            .map_err(denied)?;
        let cal_board =
            calibration_policy::Board::new_51(factory, self.device.id, assets).map_err(denied)?;
        let board = radio_policy_51::Board::new(
            self.lifecycle,
            factory,
            self.device.id,
            assets,
            profile,
            &plan,
            self.firmware_phycap().ok_or(power::Error::Unsupported)?,
        )
        .map_err(denied)?;
        let RadioPreflight51 {
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
        self.qualification_51 = Some(qualification);
        if self.coex_ready || coex.state() != coex_native::State::New {
            return Err(power::Error::Terminal);
        }
        let protocol = coex_native::Protocol51::for_version(assets.firmware_version())
            .ok_or(power::Error::Unsupported)?;
        self.radio_access()?;
        let cut = self
            .factory
            .as_ref()
            .and_then(|factory| factory.identity())
            .ok_or(power::Error::Unsupported)?
            .cut();
        // core.c rtw89_read_chip_ver: `hal->acv` = XTAL_SI_CV[3:0], which
        // rtw8851b_btc_set_rfe reports as `kt_ver_adie`.
        self.calibration_access()?;
        // SAFETY: current signed RTL8851B records installed above; same
        // serialized retained owner, Native Io encloses the transaction.
        let acv = unsafe { crate::rtw89::radio_shutdown::xtal_read(self, XTAL_SI_CV) }.await? & 0xf;
        // core.c rtw89_core_start: rtw89_btc_ntfy_init precedes
        // rtw89_phy_dm_init. SAFETY: current signed RTL8851B records; same
        // retained owner, CMAC TX closed, no BT/PTA producer.
        unsafe { coex.prepare_51(self, rfe, cut, acv, protocol) }
            .await
            .map_err(|_| power::Error::Access)?;
        self.coex_ready = true;
        let factory = self.factory.as_ref().ok_or(power::Error::Unsupported)?;
        let identity = factory.identity().ok_or(power::Error::Unsupported)?;
        let calibration = *tables.calibration_51().ok_or(power::Error::Unsupported)?;
        if identity.chip() != ChipId::Rtl8851B
            || crate::rtw89::factory_51::Calibration::from_factory(factory) != Some(calibration)
        {
            return Err(power::Error::Access);
        }
        let rfe = identity.calibration().rfe_type;
        let cut = identity.cut();
        let gain = tables.gain().ok_or(power::Error::Unsupported)?.clone();
        let tracking = rfk::n51_tssi::Tracking::from_assets(assets).map_err(denied)?;
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
                radio_51::Inputs {
                    gain: &gain,
                    calibration: &calibration,
                    power: &plan,
                    tracking: &tracking,
                    channel: profile,
                },
            )
        }
        .await
        .map_err(crate::rtw89::radio_c::error)?;
        if owner.state() != radio_51::State::Ready || owner.channel() != Some(profile) {
            return Err(power::Error::Terminal);
        }
        let qualification = self.qualification_51.clone().ok_or(power::Error::Access)?;
        qualification.current().map_err(denied)?;
        if qualification.active() != profile {
            return Err(power::Error::Access);
        }
        self.channel = Some((OperatingChannel::legacy(profile.primary()), owner.epoch()));
        // core.c rtw89_core_start ends with the radio Ready for mac80211.
        self.ordinary = Some(OrdinaryGrant::N51(qualification));
        Ok(())
    }

    /// RTL8851B counterpart of `retune_radio_c` for one typed `profile`
    /// (2.4GHz 20MHz/HT40, 5GHz 20/40/80MHz) on the Ready radio: drain,
    /// withhold the RTL8851B ordinary grant, `select` the profile's signed
    /// `N51B`/`N51C` envelope, `radio_51::Radio::retune` (core.c
    /// `rtw89_set_channel` -> rtw8851b.c `rtw8851b_set_channel`, then
    /// `rtw89_chip_rfk_channel` -> `rtw8851b_rfk_channel`), then reinstall
    /// the same grant. RTL8851B sends no RF_GET_MCCCH (its `rfk_channel`
    /// has no `rtw89_fw_h2c_rf_ntfy_mcc` call).
    ///
    /// Admission mirrors `prepare_radio_51`: the identity is rebound to this
    /// exact factory/assets/plan (`radio_policy_51::Board::new` +
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
    pub(in crate::rtw89) async unsafe fn retune_radio_51(
        &mut self,
        owner: &mut radio_51::Radio,
        tables: &radio_init::Init,
        assets: &radio_assets::Assets,
        profile: Profile,
        linked: bool,
    ) -> Result<u32, power::Error> {
        if self.chip != ChipId::Rtl8851B {
            return Err(power::Error::Unsupported);
        }
        self.radio_profile_current()?;
        self.ordinary_current()?;
        if owner.state() != radio_51::State::Ready
            || self.full_qualification.is_some()
            || !self.coex_ready
            || !self.nctl_ready
        {
            return Err(power::Error::Terminal);
        }
        if !radio_policy_51::admissible(profile) {
            return Err(power::Error::Unsupported);
        }
        if owner.channel() == Some(profile) {
            return Ok(owner.epoch());
        }
        let qualification = self
            .qualification_51
            .clone()
            .ok_or(power::Error::Terminal)?;
        if !self.ordinary.as_ref().is_some_and(
            |grant| matches!(grant, OrdinaryGrant::N51(q) if Arc::ptr_eq(q, &qualification)),
        ) {
            return Err(power::Error::Terminal);
        }
        if !qualification.channel_allowed(profile).map_err(denied)? {
            return Err(power::Error::Unsupported);
        }
        let factory = self.factory.as_ref().ok_or(power::Error::Unsupported)?;
        let identity = factory.identity().ok_or(power::Error::Unsupported)?;
        if identity.chip() != ChipId::Rtl8851B {
            return Err(power::Error::Access);
        }
        let rfe = identity.calibration().rfe_type;
        let plan = radio_power_c::Plan::from_elements_51(assets.elements(), rfe, profile)
            .map_err(denied)?;
        let board = radio_policy_51::Board::new(
            self.lifecycle,
            factory,
            self.device.id,
            assets,
            profile,
            &plan,
            self.firmware_phycap().ok_or(power::Error::Unsupported)?,
        )
        .map_err(denied)?;
        if !qualification.channel_matches(board) {
            return Err(power::Error::Access);
        }
        let calibration = *tables.calibration_51().ok_or(power::Error::Unsupported)?;
        if crate::rtw89::factory_51::Calibration::from_factory(factory) != Some(calibration) {
            return Err(power::Error::Access);
        }
        let gain = tables.gain().ok_or(power::Error::Unsupported)?.clone();
        let tracking = rfk::n51_tssi::Tracking::from_assets(assets).map_err(denied)?;
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
        // Close ordinary publication; RFK runs inside the retained RTL8851B
        // program (`Port`/`calibration_access`) whose envelope is now the
        // target profile's signed record over its occupied span.
        let grant = self.ordinary.take().ok_or(power::Error::Terminal)?;
        self.channel = None;
        qualification.select(profile).map_err(denied)?;
        // SAFETY: caller contract; queues drained and grant withheld above.
        unsafe {
            owner.retune(
                self,
                radio_51::Inputs {
                    gain: &gain,
                    calibration: &calibration,
                    power: &plan,
                    tracking: &tracking,
                    channel: profile,
                },
            )
        }
        .await
        .map_err(crate::rtw89::radio_c::error)?;
        self.radio_profile_current()?;
        if owner.state() != radio_51::State::Ready
            || owner.channel() != Some(profile)
            || qualification.active() != profile
        {
            return Err(power::Error::Terminal);
        }
        qualification.current().map_err(denied)?;
        self.channel = Some((OperatingChannel::legacy(profile.primary()), owner.epoch()));
        // RX admission follows the programmed width (as the B/C retune), VHT
        // rates only on a 5GHz wide channel.
        if let Some(core) = self.station_runtime.core.as_mut() {
            let width = profile.width() as u8;
            core.set_operating_width(width, width != 0 && profile.is_5ghz());
        }
        // ieee80211_offchannel_return: queues reopen only on the same grant.
        self.ordinary = Some(grant);
        Ok(owner.epoch())
    }

    /// One core.c `rtw89_track_work` RF step on the Ready RTL8851B radio
    /// (`radio_51::Radio::track`: thermal update + `rtw8851b_rfk_track`).
    /// Linux skips the work while `rtwdev->scanning` (no access). Runs only
    /// with the current RTL8851B ordinary grant on a started, awake,
    /// non-calibrating station; a failed step terminalizes this Native.
    ///
    /// # Safety
    /// Same retained Startup owner that prepared `owner`; no concurrent
    /// RFK/PHY/reset/PM owner (track work runs under the station's lock).
    pub(in crate::rtw89) async unsafe fn track_radio_51(
        &mut self,
        owner: &mut radio_51::Radio,
        admission: &crate::rtw89::station_control::Admission,
        scanning: bool,
    ) -> Result<(), power::Error> {
        if self.chip != ChipId::Rtl8851B {
            return Err(power::Error::Unsupported);
        }
        if self.sleep_blocked {
            return Err(power::Error::Terminal);
        }
        admission.check()?;
        self.ordinary_current()?;
        if scanning {
            return Ok(());
        }
        if !self.station_runtime.started()
            || self.calibrating.is_some()
            || owner.state() != radio_51::State::Ready
            || !self.ordinary.as_ref().is_some_and(|grant| {
                matches!(grant, OrdinaryGrant::N51(q)
                    if self.qualification_51.as_ref().is_some_and(|own| Arc::ptr_eq(q, own)))
            })
        {
            return Err(power::Error::Terminal);
        }
        crate::rtw89::station_control::awake(&mut self.io)?;
        // SAFETY: caller contract; every access is admitted by the retained
        // RTL8851B program (`calibration_access`) on the active profile.
        let result = unsafe { owner.track(self, false) }.await;
        if result.is_err() {
            self.fail();
            return Err(power::Error::Terminal);
        }
        Ok(())
    }
}
