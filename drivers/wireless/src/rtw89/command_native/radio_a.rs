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
                || self.receive.state() != crate::rtw89::rx_dma::State::Polling
                || self.calibration.is_some()
                || self.qualification_a.is_some()
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
    /// channel RFK: the native operating channel remains unset until the
    /// live thermal/TSSI prerequisites and channel RFK are composed.
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
        let factory = self.factory.as_ref().ok_or(power::Error::Unsupported)?;
        let rfe = factory
            .identity()
            .ok_or(power::Error::Unsupported)?
            .calibration()
            .rfe_type;
        let plan = radio_power_c::Plan::from_elements_a(assets.elements(), rfe, profile)
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
        if owner.state() != radio_a::State::Ready
            || owner.programmed_channel() != Some(profile)
            || owner.channel().is_some()
        {
            return Err(power::Error::Terminal);
        }
        let qualification = self.qualification_a.clone().ok_or(power::Error::Access)?;
        qualification.current().map_err(denied)?;
        if qualification.active() != profile {
            return Err(power::Error::Access);
        }
        // Keep Native.channel unset: programming alone does not establish
        // calibrated RF. Existing station/AP gates remain closed until
        // the separate live-input/channel-RFK continuation completes.
        self.ordinary = Some(OrdinaryGrant::A(qualification));
        Ok(())
    }
}
