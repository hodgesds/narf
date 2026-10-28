// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Full B radio qualification and source composition on the same retained
//! Native. No generic packet adapter can manufacture its ordinary receipt.
use super::*;
use crate::rtw89::{
    power, radio_assets, radio_full, radio_init, radio_policy, radio_power, rfk, tssi,
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
                radio_policy::Board::new(
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
                        radio_policy::Board::new(
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
                        radio_policy::Board::new(
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
    pub(in crate::rtw89) fn station_firmware_ra_allowed(&self) -> Result<bool, power::Error> {
        self.full_radio_scope()
            .ok_or(power::Error::Unsupported)?
            .allows(radio_policy::Program::FirmwareRa)
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
            let board = radio_policy::Board::new(
                factory,
                self.device.id,
                assets,
                &plan,
                self.firmware_phycap().ok_or(power::Error::Unsupported)?,
            )
            .map_err(denied)?;
            let qualification = radio_policy::Qualification::load(board).map_err(denied)?;
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
        let board = radio_policy::Board::new(
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
        let mut mcc = [0u8; 20];
        for at in [0, 4, 16] {
            mcc[at..at + 4].copy_from_slice(&1u32.to_le_bytes());
        }
        self.runtime_command(2, 0x0a, 2, &mcc, false, super::station::Permit::Legacy)
            .await?;
        self.phy_profile_current()?;
        if owner.state() != radio_full::State::Ready {
            return Err(power::Error::Terminal);
        }
        let qualification = self.full_qualification.take().ok_or(power::Error::Access)?;
        qualification.current().map_err(denied)?;
        self.ordinary = Some(OrdinaryGrant { qualification });
        Ok(())
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
