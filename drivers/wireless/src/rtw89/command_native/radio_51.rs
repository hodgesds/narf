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
    /// `rtw89_btc_ntfy_init` point, before the DM init. No ordinary grant
    /// is installed: RTL8851B station admission is not composed, so the
    /// radio is Ready with ordinary TX/ACK closed.
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
        Ok(())
    }
}
