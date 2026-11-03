// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Full B radio qualification and source composition on the same retained
//! Native. No generic packet adapter can manufacture its ordinary receipt.
use super::*;
use crate::rtw89::{
    operating_channel, power, radio_assets, radio_full, radio_init, radio_policy, radio_power, rfk,
    tssi,
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
    let plan = radio_power::Plan::from_assets_for_channel(assets, rfe, profile).map_err(denied)?;
    Ok((profile, plan))
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
    pub(in crate::rtw89) fn station_ht_allowed(&self) -> Result<bool, power::Error> {
        self.full_radio_scope()
            .ok_or(power::Error::Unsupported)?
            .allows(radio_policy::Program::Ht)
            .map_err(denied)
    }
    pub(in crate::rtw89) fn station_he_allowed(&self) -> Result<bool, power::Error> {
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
        if !crate::rtw89::track::REGISTERS.contains(&address) {
            return Err(power::Error::Access);
        }
        self.operating_current()?;
        self.radio_io()
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
        self.operating_current()?;
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
    /// `rtw89_phy_cfo_set_crystal_cap` (B: `xtal_info` NULL): XTAL SI SC_XO
    /// (0x05) then SC_XI (0x04), full byte masks, then read both back.
    pub(in crate::rtw89) async fn station_track_crystal(
        &mut self,
        cap: u8,
    ) -> Result<u8, power::Error> {
        // Linux clamps to 0..=127; the divergence lock bounds the excursion.
        self.station_track_profile()?;
        if cap > 0x7f {
            return Err(power::Error::Access);
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
    pub(in crate::rtw89) fn station_ampdu_allowed(&self) -> Result<bool, power::Error> {
        self.full_radio_scope()
            .ok_or(power::Error::Unsupported)?
            .allows(radio_policy::Program::Ampdu)
            .map_err(denied)
    }
    pub(in crate::rtw89) fn station_firmware_ra_allowed(&self) -> Result<bool, power::Error> {
        self.full_radio_scope()
            .ok_or(power::Error::Unsupported)?
            .allows(radio_policy::Program::FirmwareRa)
            .map_err(denied)
    }
    pub(in crate::rtw89) fn station_amsdu_allowed(&self) -> Result<bool, power::Error> {
        self.full_radio_scope()
            .ok_or(power::Error::Unsupported)?
            .amsdu_allowed()
            .map_err(denied)
    }
    pub(in crate::rtw89) fn station_qos_all_allowed(&self) -> Result<bool, power::Error> {
        self.full_radio_scope()
            .ok_or(power::Error::Unsupported)?
            .allows(radio_policy::Program::QosAll)
            .map_err(denied)
    }
    pub(in crate::rtw89) fn station_wmm_allowed(&self) -> Result<bool, power::Error> {
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
            for primary in (2..=13).chain(operating_channel::GHZ5) {
                let (profile, plan) =
                    channel_plan(assets, identity.calibration().rfe_type, primary)?;
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
        self.channel = Some((1, owner.epoch()));
        self.ordinary = Some(OrdinaryGrant { qualification });
        Ok(())
    }
}

/// Source B RF_GET_MCCCH body (no V0 feature for B): `rtw89_fw_h2c_rf_ntfy_mcc`
/// with `rtw89_rfk_chan_lookup` replacing slot0 for the single entity, so
/// ch_0_0 = ch_0_1 = current = primary and slot1 stays zero.
fn mccch(primary: u8) -> [u8; 20] {
    let mut mcc = [0u8; 20];
    for at in [0, 4, 16] {
        mcc[at..at + 4].copy_from_slice(&u32::from(primary).to_le_bytes());
    }
    mcc
}
impl Native {
    /// Compact mask (`operating_channel::slot`: 2.4GHz primary n = bit n,
    /// 5GHz after) of primaries with a current signed full program whose
    /// host rule currently permits active emission.
    pub(in crate::rtw89) fn admitted_channels(&self) -> Result<u64, power::Error> {
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
    /// Typed primary and retune epoch of the last completed full program.
    pub(in crate::rtw89) fn operating_channel(&self) -> Option<(u8, u32)> {
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
        let (profile, plan) = channel_plan(assets, rfe, primary)?;
        if owner.channel() == Some(profile) {
            return Ok(owner.epoch());
        }
        let qualification = self
            .ordinary
            .as_ref()
            .ok_or(power::Error::Terminal)?
            .qualification
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
            &mccch(primary),
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
        self.channel = Some((primary, owner.epoch()));
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
}
impl<'a> Port<'a> {
    pub(super) fn new(
        io: &'a mut NativeIo,
        basic: Option<&'a crate::rtw89::calibration_policy::Calibration>,
        full: Option<Arc<radio_policy::Qualification>>,
    ) -> Self {
        Self { io, basic, full }
    }
    fn current<T>(
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
            .or_else(|| self.ordinary.as_ref().map(|g| g.qualification.clone()))
    }
    pub(super) fn radio_io(&mut self) -> Result<Port<'_>, power::Error> {
        self.register_access()?;
        let full = self.full_radio_scope();
        Ok(Port::new(&mut self.io, self.calibration.as_ref(), full))
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
        self.phy_profile_current().map_err(rfk::Error::Register)?;
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
