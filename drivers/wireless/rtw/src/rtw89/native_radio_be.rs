// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Retained concrete RTL8922A closed radio composition over actual selected
//! assets/factory/NORMAL/PHYcap. N22P retains its explicit partial MAC1-off
//! program. Separately measured N22W completes DM and channel RFK with owned
//! MAC1 power and static source WLAN-only arbitration; both keep packets closed.
use super::{
    be_coex, be_mac1, be_path, be_qualification, be_wlan_qualification, channel_be,
    efuse_be::checked::Snapshot,
    mac_pre_init_8922a::HalChipVer,
    native_radio_be_io::{Port, Registers},
    operating_channel_c::{Band, Profile},
    phy_operating_be,
    power::{self, Io},
    prepared_8922a::checked::CheckedPrepared,
    radio_assets::Assets,
    radio_be::{self, Tables},
    radio_init::{self, Interface as _},
    radio_power_be,
    radio_table::Pair,
    rf_access_be,
    rfk::{
        self, be_channel, be_features::Features, be_late, be_notify, be_tssi, c_tssi,
        Interface as _,
    },
};
use core::sync::atomic::AtomicBool;
use narf_bus::{BusDevice, BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, Write};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Error {
    Qualification(super::calibration_policy::Error),
    State,
    Power(power::Error),
    Init(radio_init::Error),
    Radio(radio_be::Error),
    Rfk(rfk::Error),
}
impl From<power::Error> for Error {
    fn from(e: power::Error) -> Self {
        Self::Power(e)
    }
}
impl From<radio_init::Error> for Error {
    fn from(e: radio_init::Error) -> Self {
        Self::Init(e)
    }
}
impl From<radio_be::Error> for Error {
    fn from(e: radio_be::Error) -> Self {
        Self::Radio(e)
    }
}
impl From<rfk::Error> for Error {
    fn from(e: rfk::Error) -> Self {
        Self::Rfk(e)
    }
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum State {
    #[default]
    New,
    Busy,
    PartialMac1Off,
    ClosedWlanCalibrated,
}
#[derive(Default)]
pub(super) struct Radio {
    state: State,
    qualification: Option<be_qualification::Partial>,
    wlan: Option<be_wlan_qualification::WlanOnly>,
    mac1: be_mac1::Window,
    coex: be_coex::Owner,
    channel_rfk: be_channel::Channel,
    tracking: Option<c_tssi::Tracking>,
    rf: rf_access_be::Rf,
    operating: phy_operating_be::Operating,
    paths: be_path::Paths,
    channel_bracket: be_path::Bracket,
    context: be_notify::Context,
    late: be_late::Late,
    // Source-generated state is deliberately distinct from a calibrated
    // channel/RadioReady. Coex-dependent RFK and station gates never open.
    programmed: Option<Profile>,
    power_plan: Option<radio_power_be::Plan>,
}
pub(super) struct NativeOwner<'a> {
    pub(super) prepared: &'a mut CheckedPrepared,
    pub(super) region: &'a MmioRegion,
    pub(super) authority: &'a Cap<BusDeviceCap, Write>,
    pub(super) cancelled: &'a AtomicBool,
}
pub(super) struct Sources<'a> {
    pub(super) device: BusDevice,
    pub(super) factory: &'a Snapshot,
    pub(super) chip: HalChipVer,
    pub(super) assets: &'a Assets,
    pub(super) tables: &'a Tables,
    pub(super) features: Features,
}
impl Radio {
    /// Inert historical metadata ONLY for the negative source-revocation
    /// boundary. No RF effect, parsed report or packet readiness is produced.
    #[cfg(any(test, feature = "kernel-test"))]
    pub(super) fn fixture_packet_refusal_source(wlan: be_wlan_qualification::WlanOnly) -> Self {
        Self {
            state: State::ClosedWlanCalibrated,
            wlan: Some(wlan),
            operating: phy_operating_be::Operating::fixture_packet_refusal_metadata(),
            mac1: be_mac1::Window::fixture_packet_refusal_metadata(),
            coex: be_coex::Owner::fixture_packet_refusal_metadata(),
            late: be_late::Late::fixture_packet_refusal_metadata(),
            channel_rfk: be_channel::Channel::fixture_packet_refusal_metadata(),
            programmed: Some(Profile::INITIAL),
            ..Self::default()
        }
    }
    pub(super) fn with_packet_preflight<T, E: From<power::Error>>(
        &self,
        operation: impl FnOnce() -> Result<T, E>,
    ) -> Result<T, E> {
        if self.state != State::ClosedWlanCalibrated
            || self.operating.state() != phy_operating_be::State::CompleteMac1Restored
            || self.mac1.state() != be_mac1::State::CompleteOff
            || self.coex.state() != be_coex::State::WlanOnly
            || self.channel_rfk.calibrated() != Some(Profile::INITIAL)
            || self.late.state() != be_late::State::Calibrated
            || self.programmed != Some(Profile::INITIAL)
        {
            return Err(power::Error::Terminal.into());
        }
        self.wlan
            .as_ref()
            .ok_or_else(|| E::from(power::Error::Terminal))?
            .with_current(operation)
    }
    pub(super) fn state(&self) -> State {
        self.state
    }
    pub(super) fn programmed(&self) -> Option<Profile> {
        matches!(
            self.state,
            State::PartialMac1Off | State::ClosedWlanCalibrated
        )
        .then_some(self.programmed)
        .flatten()
    }
    pub(super) fn late_report(&self, kind: rfk::be_rfk::ReportKind) -> Option<rfk::be_rfk::Report> {
        self.late.report(kind)
    }
    /// # Safety
    /// Same exclusive original function and original completed checked
    /// FW/System/closedTRX owner which produced every supplied source fact.
    /// No IRQ/ordinary rings/net/station publication or concurrent reset.
    /// Failure/drop leaves this retained owner Busy and pins all DMA; no
    /// replacement of this owner, grant, token or report stream is allowed.
    pub(super) async unsafe fn prepare_partial(
        &mut self,
        native: NativeOwner<'_>,
        sources: Sources<'_>,
    ) -> Result<(), Error> {
        let NativeOwner {
            prepared,
            region,
            authority,
            cancelled,
        } = native;
        let Sources {
            device,
            factory,
            chip,
            assets,
            tables,
            features,
        } = sources;
        if self.state != State::New {
            return Err(Error::State);
        }
        self.state = State::Busy;
        prepared.partial_radio_ready()?;
        let phycap = prepared.phycap().ok_or(Error::State)?;
        let paths = be_path::Config::from_receipt(phycap)?;
        let (tx_nss, rx_nss, _, _, _) = phycap.topology();
        // All pure input/table/power preflight precedes the first radio
        // effect. The historical N22A-v1 subset cannot reach this loader.
        let power_channel =
            radio_power_be::Channel::new(Band::Ghz2, 1, 1, radio_power_be::Bw::Mhz20)
                .ok_or(Error::State)?;
        self.power_plan = Some(radio_power_be::Plan::from_assets(
            assets,
            factory.factory.rfe_type,
            power_channel,
        )?);
        let facts = be_qualification::Facts {
            device: device.id,
            factory,
            chip,
            assets,
            features,
            phycap,
        };
        // Select exactly once, before effects. Missing N22W uses only the
        // separately sealed partial program; no retained owner can upgrade
        // after a missing record or after entering Busy.
        self.wlan = be_wlan_qualification::WlanOnly::load(&facts).map_err(Error::Qualification)?;
        let qualification = if let Some(wlan) = &self.wlan {
            self.tracking = Some(c_tssi::Tracking::from_assets(assets)?);
            be_qualification::Grant::Wlan(wlan)
        } else {
            self.qualification =
                Some(be_qualification::Partial::load(&facts).map_err(Error::Qualification)?);
            be_qualification::Grant::Partial(self.qualification.as_ref().ok_or(Error::State)?)
        };
        let wlan = qualification.wlan();
        // SAFETY: original retained live function/closed stages and newly
        // loaded exact N22P facts above; no reconstructed authority/producer.
        let io = unsafe { Registers::new_scope(region, authority, qualification, cancelled) };
        let trim = factory.factory.power_trim();
        let mut port = Port {
            io,
            rf: &mut self.rf,
            prepared,
            device: device.id,
            thermal_trim: trim.thermal,
            mac1: &mut self.mac1,
            coex: wlan.then_some(&mut self.coex),
        };
        let result = async {
            // Source BB init; init_txpwr_unit NULL and bb_reset empty. Gain
            // decode already pure; cfg_type15 direct words are actual effects.
            radio_init::bb_be(&mut port, tables.bb()).await?;
            for &(address, mask, value) in tables.gain().direct() {
                field(&mut port, 0x20000 + address, mask, value)?;
            }
            phy_operating_be::post_bb(&mut port)?;
            // RF source callback is config_rf_reg_v1 even on RF-access-v2:
            // only0xfe delay, actual analog writes, direct-only H2C pages.
            for path in 0..2 {
                for &Pair(address, value) in tables.rf(path) {
                    if address == 0xfe {
                        port.delay_us(50_000).await;
                        port.admit()?;
                    } else {
                        port.radio_write(path as u8, address, 0xfffff, value)
                            .await?;
                    }
                }
                for (page, bytes) in tables.rf_pages(path)?.chunks(2000).enumerate() {
                    port.radio_page(path as u8, page as u8, bytes).await?;
                }
            }
            // Source DM order. Only N22W admits the separate owned MAC1
            // UL power window; N22P preserves its explicit pair omission.
            // SAFETY: exact qualified partial program/actual factory inputs;
            // port checks current signed+Bus authority around every effect.
            unsafe {
                if wlan {
                    self.operating
                        .prepare_scc_complete(&mut port, &factory.factory, chip)
                        .await?;
                } else {
                    self.operating
                        .prepare_scc_partial(&mut port, &factory.factory, chip)
                        .await?;
                }
            }
            radio_init::nctl_be(&mut port, tables.nctl()).await?;
            // Source rfk_init clears TSSI-mode flags/MCC software state;
            // these are actual software initialization, not hardware defaults.
            self.context = be_notify::Context::default();
            for (address, mask, value) in radio_be::TXPWR_REF_FIELDS {
                field(&mut port, address, mask, value)?;
            }
            // SAFETY: same exact N22P power trim and exclusive original RF-v2
            // owner; source PA/pad gating uses actual retained PHYcap bytes.
            unsafe {
                radio_be::apply_power_trim(&mut port, &trim).await?;
            }
            // SAFETY: source SCC initial profile and actual GET_FEATURE
            // topology; all tables/partial DM/NCTL/trim effects completed.
            unsafe {
                self.paths
                    .configure(&mut port, paths, Profile::INITIAL.band())
                    .await?;
            }

            if wlan {
                let protocol =
                    be_coex::Protocol::from_version(features.version()).ok_or(Error::State)?;
                // Actual retained NORMAL, RFE/cut and GET_FEATURE
                // topology; separate current N22W covers the whole static
                // source WLAN-only arbitration + calibration program.
                port.prepare_wlan_coex(
                    protocol,
                    factory.factory.rfe_type,
                    chip.cv,
                    chip.acv,
                    (tx_nss, rx_nss),
                )
                .await?;
            }

            // Native explicitly programs channel1 before init-late instead
            // of assuming the selected RF table's reset/default channel.
            self.channel_bracket
                .enter(&mut port, Profile::INITIAL.band())
                .await?;
            channel_be::program_set_channel_mac(&mut port, Profile::INITIAL)?;
            channel_be::program_set_channel_bb_with_gain(
                &mut port,
                Profile::INITIAL,
                tables.gain(),
                &factory.calibration,
            )?;
            // SAFETY: current measured channel1/20MHz, exact source RF-v2
            // port, source reset bracket held and ordinary CMAC bits closed.
            unsafe {
                channel_be::program_set_channel_rf(&mut port, Profile::INITIAL, chip.cv).await?;
            }
            self.power_plan.as_ref().ok_or(Error::State)?.visit(
                0,
                chip.cv,
                |address, mask, value| {
                    // Source DAG disabled in this measured partial profile. The
                    // signed antenna gain still bounds calibration EIRP through
                    // calibration_policy; it is not a made-up path difference.
                    field(&mut port, address, mask, value).map_err(rfk::Error::from)
                },
            )?;
            self.channel_bracket
                .exit(&mut port, Profile::INITIAL.band())
                .await?;
            // Source SCC post_set_channel_rf does chlk_reload only. DBCC's
            // synthesizer transitions/pre/postBB are not source SCC effects.
            // SAFETY: actual complete source channel effects above; fresh
            // software RFK context and current retained firmware version.
            unsafe {
                self.context
                    .reload(&mut port, Profile::INITIAL, features)
                    .await?;
            }
            self.programmed = Some(Profile::INITIAL);
            // Native divergence: no ordinary HCI/rings/RUNNING/BT radio-on
            // opening. N22P explicitly measures this closed init-late run;
            // transport is actual current CH12/C2H and reports are retained.
            // SAFETY: exact measured closed partial SCC profile after all
            // source prerequisites above; no normal-RX/packet authority.
            unsafe {
                self.late
                    .run(
                        &mut port,
                        Profile::INITIAL,
                        factory.factory.rfe_type,
                        features,
                        &self.context,
                    )
                    .await?;
            }
            if wlan {
                let tssi = be_tssi::Inputs {
                    profile: &factory.calibration.tssi,
                    // Source 8922A PHYcap has no TSSI-trim producer.
                    trim: [[0; 8]; 2],
                    trim_6g: [[0; 16]; 2],
                    tracking: self.tracking.as_ref().ok_or(Error::State)?,
                    rfe_type: factory.factory.rfe_type,
                    cv: chip.cv,
                };
                port.coex_switch_band().await?;
                // SAFETY: exact source-programmed home channel/context,
                // completed complete DM and WLAN-only arbitration owner;
                // original retained transport supplies each RFK report.
                unsafe {
                    self.channel_rfk
                        .band_changed(&mut port, Profile::INITIAL, &tssi)
                        .await?;
                    self.channel_rfk
                        .rfk_channel(&mut port, Profile::INITIAL, &tssi, features, &self.context)
                        .await?;
                }
            }
            port.admit()?;
            Ok::<(), Error>(())
        }
        .await;
        if result.is_err() {
            port.prepared.poison_radio();
            return result;
        }
        self.state = if wlan {
            State::ClosedWlanCalibrated
        } else {
            State::PartialMac1Off
        };
        Ok(())
    }
}
fn field(io: &mut impl Io, address: u32, mask: u32, value: u32) -> Result<(), power::Error> {
    let old = io.read32(address)?;
    if old == u32::MAX {
        return Err(power::Error::Gone);
    }
    io.write32(
        address,
        (old & !mask) | ((value << mask.trailing_zeros()) & mask),
    )
}
