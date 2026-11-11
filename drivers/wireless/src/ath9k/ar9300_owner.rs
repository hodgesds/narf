// SPDX-License-Identifier: GPL-2.0-or-later
//! AR9380/AR9390 (`0x0030` PCIe, `hw.h::AR9300_DEVID_PCIE`), AR9580
//! (`0x0033`, `hw.h::AR9300_DEVID_AR9580`), AR9462 (`0x0034`,
//! `hw.h::AR9300_DEVID_AR9462`) and AR9565 (`0x0036`,
//! `hw.h::AR9300_DEVID_AR9565`) probe and dual-band 20 MHz
//! legacy station owner; the AR9485 (`0x0032`,
//! `hw.h::AR9300_DEVID_AR9485_PCIE`) and AR1111 (`0x0037`,
//! `hw.h::AR9485_DEVID_AR1111`) probe as single-chain 2.4 GHz-only parts
//! on the same owner.
//!
//! The AR9580 runs the AR9300 path unchanged (Linux `AR_SREV_9300` is true
//! for it): only its `AR_SREV` revision split, the `ar9580_1p0` INI and
//! gain tables (`ar9003::ini::Tables::for_revision`) and its `N95A`
//! record differ. The AR9462 likewise runs the shared AR9003 path: only
//! its own macVersion, the `ar9462_2p0`/`ar9462_2p1` INI and gain tables
//! (plus the sys2ant postamble and RX-gain mode 2/3 overrides), its
//! two-chain masks and its `N46A` record differ. The AR9565 likewise
//! runs the shared AR9003 path: only its own macVersion, the
//! `ar9565_1p0`/`ar9565_1p1` INI and gain tables (1.1 owns only its radio
//! postamble), its one-chain masks and its `N65A` record differ.
//! The AR9485 likewise
//! differs only in its `AR_SREV` revision rule (macVersion 0x240, macRev
//! \>= 1), the `ar9485_1_1` INI and gain tables, and its `N48A` record;
//! its EEPROM masks are single-chain and its `opFlags` enable 2.4 GHz
//! only, so the shared `channel_supported` gate already refuses 5 GHz
//! for it.
//!
//! `pci.c::ath_pci_probe` → `hw.c::ath9k_hw_init` order: the chip is
//! identified through its `AR_SREV` and restored `ar9300_eeprom`
//! (`ar9003::identify`), prepared inactive for the 20 MHz primary
//! (`ar9003::phy::prepare`, `ath9k_regd_get_ctl` over the map's
//! `regDmn[0]`) and admitted only by a signer-verified `N93A`/`N95A`/
//! `N46A`/`N65A` board record
//! bound to that exact map and preparation. Calibration
//! (`ar9003::calib::Calibration::run`) runs after the power plan is
//! re-planned and programmed at the signed ceiling under the dual-band
//! host permission (`ath9k_hw_apply_txpower`); the EDMA packet owner
//! (`ar9003::packet::Packet`) then carries the station with the band's MAC
//! clock, behind the shared station/interface owners.
//!
//! Hang recovery (FATAL, BB watchdog, TX hang, failed calibration, RX
//! inactivity) is the in-place `ath_reset` ([`reset_in_place`]), which
//! keeps the station generation and its association. Every retune,
//! terminal-station recovery and resume is a generation reset:
//! `hw.c::ath9k_hw_chip_reset` (`ATH9K_RESET_COLD` after FULL_SLEEP or
//! when `AR_Q_TXE`/`AR_CR_RXE` are still set, else WARM; then
//! `ath9k_hw_setpower(AWAKE)`), an `AR_SREV` re-check, and a full
//! `ath9k_hw_reset` preparation (no fast channel change). The target's
//! signed record and dual-band permission are proven before the old
//! generation is retired. DFS, NO_IR and indoor-only 5 GHz channels are
//! refused by `Permission::from_domain_dual`. The `ath_hw`-lifetime IQ
//! accumulators (`IqTotals`) carry across generations. No HT, EDCA, QoS,
//! block-ack or power-save program exists for this owner.
use super::{
    admission, ar9003, calibration, channels, interface, packet, packet_native, phy, station,
    BringUpError, RetainedRadio, CLAIMED_ADDRESS, CONTROL,
};
use crate::qualcomm_regulatory::Factory;
use alloc::{boxed::Box, sync::Arc};
use core::fmt::Write as _;
use narf_bus::{BusDevice, BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, Write};
use narf_lib::{mutex::Mutex, sync::IrqSafeSpinLock};

use super::identity::{self, RegisterIo};

/// The initial primary the signed record and calibration bind (channel 1).
const PRIMARY: u16 = 2412;
/// The highest AR9003 register this owner touches is the last
/// `ar9485_1_1_radio_core` row (`0x16c44`); the 9300/9580 radio cores
/// end lower (`0x16bd4`).
const REQUIRED_BAR: u64 = 0x1_6c48;
/// `reg.h::AR_CFG_LED`.
const AR_CFG_LED: u64 = 0x1f04;
/// `reg.h::AR_CR` and `AR_CR_RXE(ah)` for `AR_SREV_9300_20_OR_LATER`.
const AR_CR: u64 = 0x0008;
const AR_CR_RXE_9300: u32 = 0x0000_000c;
/// `reg.h::AR_Q_TXE`.
const AR_Q_TXE: u64 = 0x0840;
/// Terminal-generation and calibration-timer poll interval (the AR9280
/// owner's); `ar9003::calib::Periodic` owns the Linux
/// `ath_ani_calibrate` intervals.
const SUPERVISE_NS: u64 = 500_000_000;
/// (PCI device, unique bus-match name).
pub(super) const DEVICES: [(u16, &str); 6] = [
    (0x0030, "ath9k-ar9300"),
    (0x0033, "ath9k-ar9580"),
    (0x0034, "ath9k-ar9462"),
    (0x0036, "ath9k-ar9565"),
    (0x0032, "ath9k-ar9485"),
    (0x0037, "ath9k-ar1111"),
];

pub(super) struct Owner {
    mmio: MmioRegion,
    device: BusDevice,
    cap: Cap<BusDeviceCap, Write>,
    revision: ar9003::Revision,
    /// `ah->config.pll_pwrsave` resolved for this exact subsystem.
    pll_pwrsave: ar9003::serdes::PllPwrsave,
    /// PCI config `0x70c` word (`ath_pci_aspm_init`'s `aspm_l1_fix`);
    /// the AR9462 SerDes restore consumes it, 0 when the read failed.
    aspm_l1_fix: u32,
    /// `ah->WARegVal`.
    wa: u32,
    identity: ar9003::eeprom::Identity,
    image: Box<ar9003::power::Image>,
    /// `ath9k_hw_reset`'s pre-reset `AR_CFG_LED` of this generation.
    led: u32,
    /// Inactive preparation of the current physical generation.
    prepared: ar9003::phy::Prepared,
    /// Primary of the current generation; its record is `grant`.
    primary: u16,
    grant: Arc<admission::Grant>,
    radio: ar9003::calib::Calibration,
    /// `ah->totalPowerMeasI/Q`, `totalIqCorrMeas` (never cleared in Linux).
    totals: Arc<IrqSafeSpinLock<ar9003::calib::IqTotals>>,
    station: Option<RetainedRadio>,
    attempted: bool,
    /// Physical generation; bumped by each successful generation reset.
    generation: u32,
    removed: bool,
    /// System suspend parked the chip in FULL_SLEEP; only resume reopens it.
    suspended: bool,
    /// `ah->chip_fullsleep`: the next chip reset is COLD.
    fullsleep: bool,
    /// Retirement could not prove DMA stopped; the address stays reserved.
    pinned: bool,
    /// `ath9k_init_wow`: present only for an AR9462 whose PCI subsystem
    /// carries `ATH9K_PCI_WOW` (`pci.c`); `ah->wow`.
    wow: Option<ar9003::wow::Wow>,
    /// `ATH_OP_WOW_ENABLED`: system suspend left the associated station
    /// armed in WoW sleep instead of retiring it.
    wow_sleeping: bool,
}
pub(super) type Shared = Arc<Mutex<Owner>>;
static OWNER: IrqSafeSpinLock<Option<Shared>> = IrqSafeSpinLock::new(None);
/// `wiphy->wowlan` of the bound radio (`wow.c::ath9k_init_wow`).
static WOWLAN_SUPPORT: IrqSafeSpinLock<Option<narf_wireless::WowlanSupport>> =
    IrqSafeSpinLock::new(None);
/// `wiphy->wowlan_config` (`nl80211_set_wowlan`).
static WOWLAN: IrqSafeSpinLock<Option<narf_wireless::WowlanConfig>> = IrqSafeSpinLock::new(None);

/// `wow.c::ath9k_init_wow`'s `wiphy->wowlan`: magic packet and disconnect
/// wake, `ath9k_wowlan_support` (AR9462 2.0+: `MAX_NUM_PATTERN - 2` user
/// patterns) or the legacy set, `pattern_min_len` 1, `pattern_max_len`
/// `MAX_PATTERN_SIZE`, no packet offset.
fn wowlan_support_for(revision: &ar9003::Revision) -> narf_wireless::WowlanSupport {
    let support = ar9003::wow::WowlanSupport::for_revision(revision);
    narf_wireless::WowlanSupport {
        disconnect: true,
        magic_packet: true,
        max_patterns: support.n_patterns(),
        min_pattern_len: 1,
        max_pattern_len: support.pattern_max_len() as u16,
        ..Default::default()
    }
}

/// The bound AR9462 WoW subsystem's `wiphy->wowlan`; `None` for every
/// other part.
pub(super) fn wowlan_support() -> Option<narf_wireless::WowlanSupport> {
    *WOWLAN_SUPPORT.lock()
}

/// `nl80211_set_wowlan` against `wowlan_support` (cfg80211's own
/// validation: pattern count, lengths, mask size, no offset; GTK-rekey
/// failure and net-detect are not advertised).
pub(super) fn set_wowlan(config: Option<narf_wireless::WowlanConfig>) -> Result<(), i32> {
    let support = wowlan_support().ok_or(narf_wireless::EOPNOTSUPP)?;
    if let Some(config) = &config {
        let bad = config.gtk_rekey_failure
            || config.net_detect.is_some()
            || config.patterns.len() > usize::from(support.max_patterns)
            || config.patterns.iter().any(|p| {
                p.offset != 0
                    || p.pattern.is_empty()
                    || p.pattern.len() > usize::from(support.max_pattern_len)
                    || p.mask.len() != p.pattern.len().div_ceil(8)
            });
        if bad {
            return Err(22); // EINVAL
        }
    }
    *WOWLAN.lock() = config;
    Ok(())
}

pub(super) fn wowlan_config() -> Option<narf_wireless::WowlanConfig> {
    WOWLAN.lock().clone()
}

/// `ath9k_regd_get_ctl` at `frequency` for the map's `regDmn[0]`:
/// `ath_regd_get_band_ctl` (initial DFS region unset) | `CTL_11G` on
/// 2.4 GHz, | `CTL_11A` on 5 GHz.
fn ctl_at(identity: &ar9003::eeprom::Identity, frequency: u16) -> Result<u16, BringUpError> {
    let factory = Factory::from_eeprom(u32::from(identity.regulatory_domains[0]))
        .map_err(|_| BringUpError::BadCalibration)?;
    Ok(if frequency >= 4800 {
        phy::rates::initial_ctl_5ghz(factory)
    } else {
        phy::rates::initial_ctl(factory)
    })
}

/// The preparation `ar9003::phy::prepare` produces at `frequency` with the
/// inactive (zero) probe power limit.
fn prepared_at(o: &Owner, frequency: u16) -> Result<ar9003::phy::Prepared, BringUpError> {
    let ctl = ctl_at(&o.identity, frequency)?;
    ar9003::phy::expected(
        &o.revision,
        &o.identity,
        o.pll_pwrsave,
        &o.image,
        frequency,
        ctl,
        0,
    )
}

/// The signed `N93A` (AR9580: `N95A`) record keyed to `frequency`.
fn record(o: &Owner, frequency: u16) -> Result<Arc<admission::Grant>, BringUpError> {
    let prepared = prepared_at(o, frequency)?;
    let ctl = ctl_at(&o.identity, frequency)?;
    let facts = admission::Facts::new_ar9003(
        &o.device.id,
        &o.revision,
        &o.identity,
        &prepared,
        &o.image,
        frequency,
        ctl,
    )?;
    admission::Source::Registered.load(facts)
}

/// Every primary (`channels::bit`) the map's `opFlags` enables whose
/// record verifies, plus the current primary.
fn admitted_mask(o: &Owner) -> u64 {
    let primary = channels::bit(o.primary).map_or(0, |bit| 1 << bit);
    (0..channels::CHANNEL_BITS)
        .filter(|bit| {
            channels::bit_frequency(*bit).is_some_and(|frequency| {
                ar9003::phy::channel_supported(&o.identity, frequency)
                    && record(o, frequency).is_ok()
            })
        })
        .fold(primary, |mask, bit| mask | 1 << bit)
}

/// `AR_CFG_LED` as `ath9k_hw_reset` saves it before the chip reset.
fn read_led(io: &mut impl RegisterIo) -> Result<u32, BringUpError> {
    let value = io.read32(AR_CFG_LED);
    if value == u32::MAX || !io.authorized() {
        return Err(BringUpError::DeviceGone);
    }
    Ok(value)
}

fn matches(id: &narf_bus::DeviceId) -> bool {
    id.vendor == 0x168c
        && DEVICES.iter().any(|(device, _)| *device == id.device)
        && ar9003::Chip::for_device(id.device).is_some()
}

fn bad(stage: &str, error: BringUpError) -> narf_bus::ProbeError {
    let _ = writeln!(
        narf_console::Writer,
        "  ath9k: AR9003 {} failed: {:?}",
        stage,
        error
    );
    narf_bus::ProbeError::BadDevice
}

pub(super) fn probe(
    device: BusDevice,
    cap: Cap<BusDeviceCap, Write>,
) -> Result<(), narf_bus::ProbeError> {
    if !matches(&device.id) {
        return Err(narf_bus::ProbeError::NotForThisDriver);
    }
    // Same singleton reservation as AR9285, before any hardware access.
    let previous = {
        let mut claimed = CLAIMED_ADDRESS.lock();
        let previous = *claimed;
        if previous.is_none() {
            *claimed = Some(device.addr);
        }
        previous
    };
    let occupied = previous.is_some();
    crate::qualcomm_pci::park(&device, &cap, false, previous)?;
    if occupied {
        return Err(narf_bus::ProbeError::Other(
            "ath9k singleton already owns another radio",
        ));
    }
    let mmio = crate::qualcomm_pci::map_bar_control(&device, &cap, 0)?;
    if mmio.len < REQUIRED_BAR {
        return Err(narf_bus::ProbeError::BadDevice);
    }
    let mut io = identity::Registers::new(mmio, cap);
    let identified =
        ar9003::identify(&mut io, device.id.device).map_err(|e| bad("identification", e))?;
    let revision = identified.powered.revision;
    let identity = identified.identity;
    let image = identified.restored.image;
    // `__ath9k_hw_init`'s `pll_pwrsave` resolution for this exact
    // subsystem, and the AR9462 L1-entry-latency fix word
    // (`ath_pci_aspm_init` reads PCI config `0x70c`); a failed read
    // leaves 0, which writes nothing.
    let pll_pwrsave = ar9003::serdes::PllPwrsave::resolve(
        revision.chip,
        device.id.subsystem_vendor,
        device.id.subsystem_id,
    );
    let aspm_l1_fix = if revision.chip == ar9003::Chip::Ar9462 {
        identity::invoke(&cap, || narf_bus::pci::read_config32(&cap, &device, 0x70c))
            .ok()
            .and_then(|read| read.ok())
            .unwrap_or(0)
    } else {
        0
    };
    // ath9k_hw_reset reads AR_CFG_LED from the awake chip before its
    // chip reset; here the identification power-on stands for it.
    let led = read_led(&mut io).map_err(|e| bad("AR_CFG_LED read", e))?;
    let ctl = ctl_at(&identity, PRIMARY).map_err(|e| bad("regulatory CTL", e))?;
    let prepared = ar9003::phy::prepare(
        &mut io,
        &revision,
        &identity,
        pll_pwrsave,
        &image,
        PRIMARY,
        ctl,
        0,
    )
    .map_err(|e| bad("baseband preparation", e))?;
    let expected =
        ar9003::phy::expected(&revision, &identity, pll_pwrsave, &image, PRIMARY, ctl, 0)
            .map_err(|e| bad("preparation facts", e))?;
    if prepared != expected {
        return Err(bad("preparation facts", BringUpError::BadState));
    }
    let facts = admission::Facts::new_ar9003(
        &device.id, &revision, &identity, &prepared, &image, PRIMARY, ctl,
    )
    .map_err(|e| bad("admission facts", e))?;
    let request = facts.request();
    let grant = match admission::Source::Registered.load(facts) {
        Ok(grant) => grant,
        Err(_) => {
            // Unprovisioned or foreign record: stay parked and unadmitted.
            let _ = ar9003::disable_and_sleep(&mut io, identified.powered.wa);
            let _ = writeln!(
                narf_console::Writer,
                "  ath9k: {} MAC {:02x?} unadmitted; signed board record {} absent or invalid",
                revision.chip.name(),
                identity.mac,
                request.filename
            );
            return Err(narf_bus::ProbeError::Other(
                "ath9k AR9003 board admission record absent or invalid",
            ));
        }
    };
    let _ = writeln!(
        narf_console::Writer,
        "  ath9k: {} rev {} MAC {:02x?}, EEPROM {:#x}, chains {:#x}/{:#x}; admitted, calibration pending",
        revision.chip.name(),
        revision.mac_rev,
        identity.mac,
        identity.eeprom_version,
        identity.rx_chainmask,
        identity.tx_chainmask
    );
    let (vendor, device_id) = (device.id.vendor, device.id.device);
    // ath9k_init_wow: `ATH9K_PCI_WOW` driver_data (AR9462 subsystems only).
    let wow = ar9003::wow::init_capable(
        ar9003::wow::driver_data(
            device.id.device,
            device.id.subsystem_vendor,
            device.id.subsystem_id,
        ),
        false,
    )
    .then(|| ar9003::wow::Wow::new(&revision));
    *WOWLAN_SUPPORT.lock() = wow.map(|_| wowlan_support_for(&revision));
    let owner = Arc::new(Mutex::new(Owner {
        mmio,
        device,
        cap,
        revision,
        pll_pwrsave,
        aspm_l1_fix,
        wa: identified.powered.wa,
        identity,
        image,
        led,
        prepared,
        primary: PRIMARY,
        grant,
        radio: ar9003::calib::Calibration::default(),
        totals: Arc::new(IrqSafeSpinLock::new(ar9003::calib::IqTotals::default())),
        station: None,
        attempted: false,
        generation: 0,
        removed: false,
        suspended: false,
        fullsleep: false,
        pinned: false,
        wow,
        wow_sleeping: false,
    }));
    *OWNER.lock() = Some(owner.clone());
    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from(
            DEVICES
                .iter()
                .find(|(device, _)| *device == device_id)
                .map_or("ath9k-ar9300", |(_, name)| *name),
        ),
        kind: narf_drivers::BoundKind::Net,
        pci_vid: Some(vendor),
        pci_did: Some(device_id),
        domain: narf_drivers::BoundKind::Net.default_domain(),
    });
    narf_scheduler::spawn(async move {
        let mut result = Err(BringUpError::Policy);
        for attempt in 0..120 {
            if attempt > 0 {
                narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(500_000_000)).await;
            }
            result = {
                let _control = CONTROL.lock().await;
                initialize(&owner).await
            };
            if !matches!(result, Err(BringUpError::Policy)) {
                break;
            }
        }
        match result {
            Ok(report) => {
                let _ = writeln!(
                    narf_console::Writer,
                    "ath9k: AR9003 channel1 native station published: peak CALDAC {:?} default NF {:?} dBm",
                    report.peak_caldac,
                    report.default_nf
                );
                supervise(owner).await;
            }
            Err(error) => {
                let _ = writeln!(
                    narf_console::Writer,
                    "ath9k: AR9003 channel1 bring-up closed: {:?}",
                    error
                );
            }
        }
    });
    Ok(())
}

/// `ath9k_hw_apply_txpower` at the signed ceiling, calibrate, then compose
/// the native owners.
async fn initialize(owner: &Mutex<Owner>) -> Result<ar9003::calib::Report, BringUpError> {
    let domain = narf_wireless::reg::db::ensure_domain().map_err(|_| BringUpError::Policy)?;
    if narf_net::trusted_net_authority().is_none() {
        return Err(BringUpError::Policy);
    }
    let mut o = owner.lock().await;
    if o.removed || o.attempted || o.radio.state() != ar9003::calib::State::New {
        return Err(BringUpError::BadState);
    }
    let host = calibration::Permission::from_domain_dual(&domain, o.primary)?;
    let grant = o.grant.clone();
    let permission = host.with_ceiling(grant.invoke(|| Ok(grant.ceiling(host.budget())))?);
    let command = identity::invoke(&o.cap, || narf_bus::pci::read_command(&o.cap, &o.device))
        .map_err(|_| BringUpError::DeviceGone)?
        .map_err(|_| BringUpError::DeviceGone)?;
    let mask = narf_bus::pci::cmd::BUS_MASTER
        | narf_bus::pci::cmd::MEM_SPACE
        | narf_bus::pci::cmd::INTX_DISABLE;
    if command & mask != (narf_bus::pci::cmd::MEM_SPACE | narf_bus::pci::cmd::INTX_DISABLE) {
        return Err(BringUpError::BadState);
    }
    let mut io = identity::Registers::new(o.mmio, o.cap);
    let identity = o.identity;
    let ctl = ctl_at(&identity, o.primary)?;
    // ath9k_hw_apply_txpower: the plan at min(channel, signed) ceiling.
    let plan = ar9003::power::plan(
        &o.image,
        o.primary,
        ctl,
        permission.budget(),
        identity.tx_chainmask,
    )?;
    grant.invoke(|| ar9003::power::program(&mut io, &plan))?;
    o.prepared.power = plan;
    // `ath9k_start` resets the SerDes registers before the station
    // runs (`ath9k_hw_configpcipowersave(ah, false)`): the low-power
    // array plus `AR_PCIE_PM_CTRL_ENA` and the latched `AR_WA` word.
    let tables = ar9003::ini::Tables::for_revision(&o.revision, &identity, o.pll_pwrsave);
    grant.invoke(|| {
        ar9003::serdes::configure(&mut io, &o.revision, &tables, false, o.wa, o.aspm_l1_fix)
    })?;
    let prepared = o.prepared;
    let revision = o.revision;
    // SAFETY: probe or the last generation reset identified this AR9300
    // and ran its complete inactive preparation for `prepared` (whose power
    // plan was just re-programmed); PCI parking was verified above and no
    // packet DMA exists. The async mutex serializes the whole attempt.
    let report = unsafe {
        calibrate(
            &mut o.radio,
            &mut io,
            &identity,
            &revision,
            &prepared,
            &grant,
            permission,
        )
    }
    .await?;
    // The attempt is retained before any MAC mutation.
    o.attempted = true;
    let station = compose(&mut o, report, permission).map_err(|error| {
        let _ = writeln!(
            narf_console::Writer,
            "ath9k: AR9003 native station composition closed: {:?}",
            error
        );
        BringUpError::BadState
    })?;
    drop(o);
    interface::publish(station).map_err(|error| {
        let _ = writeln!(
            narf_console::Writer,
            "ath9k: AR9003 native station publication closed: {:?}",
            error
        );
        BringUpError::BadState
    })?;
    Ok(report)
}

/// `ar9003::calib::Calibration::run` under the signed record and the
/// current dual-band host permission, re-proved at every poll.
///
/// # Safety
/// `calib::Calibration::run`'s contract: `prepared` is this chip's
/// complete inactive preparation, PCI bus mastering is off and no packet
/// DMA engine runs.
async unsafe fn calibrate(
    calibration: &mut ar9003::calib::Calibration,
    io: &mut identity::Registers,
    identity: &ar9003::eeprom::Identity,
    revision: &ar9003::Revision,
    prepared: &ar9003::phy::Prepared,
    grant: &admission::Grant,
    permission: calibration::Permission,
) -> Result<ar9003::calib::Report, BringUpError> {
    // SAFETY: forwarded from the caller's contract.
    let future = unsafe { calibration.run(io, identity, revision, prepared) };
    let mut future = core::pin::pin!(future);
    core::future::poll_fn(|cx| {
        if narf_wireless::reg::db::snapshot().is_none_or(|d| !permission.current_dual_in(&d)) {
            return core::task::Poll::Ready(Err(BringUpError::Policy));
        }
        grant
            .invoke(|| Ok(core::future::Future::poll(future.as_mut(), cx)))
            .unwrap_or(core::task::Poll::Ready(Err(BringUpError::Policy)))
    })
    .await
}

fn compose(
    o: &mut Owner,
    report: ar9003::calib::Report,
    permission: calibration::Permission,
) -> Result<RetainedRadio, packet::Error> {
    // ath9k_hw_getchan_noise before the first NF history entry: chain 0's
    // ath9k_hw_get_default_nf.
    let noise = report.default_nf[0];
    let mac = o.identity.mac;
    let channel_mask = admitted_mask(o);
    let totals = o.totals.clone();
    let periodic = ar9003::calib::Periodic::new(
        &o.revision,
        &report,
        *totals.lock(),
        narf_time::monotonic_ns() / 1_000_000,
    );
    // SAFETY: same sole calibrated AR9300 function, cap and BAR; the plan
    // was programmed at `permission`'s ceiling (which the signed grant
    // bounds) and no packet DMA was published.
    let native = unsafe {
        packet_native::Native::new_ar9300(
            o.device,
            o.cap,
            o.mmio,
            report,
            o.grant.clone(),
            permission,
            &o.identity,
            &o.image,
            &o.prepared,
            periodic,
            totals,
            channel_mask,
        )
    }?;
    ar9003::mac::prepare(&native, &o.identity, &o.image[..], mac, report.five_ghz)?;
    native.ar9300_reset_tail(o.led)?;
    let _ = native.arm_msi();
    // SAFETY: complete parked MAC/key-cache/queue preparation succeeded on
    // this same non-cloneable native adapter; prepare does not start DMA.
    let packet = unsafe { ar9003::packet::Packet::prepare(native, mac) }?;
    // `channels` routes this generation's retunes (either band) to
    // `transition`; HT40 requests fail closed (no AR9300 HT owner).
    let station = Arc::new(Mutex::new(station::Radio::new(
        packet.into(),
        mac,
        noise,
        station::NativeEnvironment {
            generation: o.generation,
        },
    )));
    o.station = Some(station.clone());
    Ok(station)
}

/// Driver-owned transition for `channels`: the retained AR9300 owner is
/// reset to `frequency` only while `generation` is still current.
pub(super) fn transition(
    frequency: u16,
    generation: u32,
) -> Option<impl core::future::Future<Output = Result<(), BringUpError>> + Send + 'static> {
    let owner = OWNER.lock().clone()?;
    Some(async move {
        reset(&owner, Some(frequency), Some(generation))
            .await
            .map(|_| ())
    })
}

/// Generation reset (Linux `ath_reset` / `ath9k_hw_reset`): `selected`
/// retunes to another primary, `None` repeats the current one (recovery
/// and resume). The target's signed record and host permission are proven
/// before the old generation is retired; its DMA stop must then be proven
/// and bus mastering must be off. `ath9k_hw_setpower(AWAKE)`, the saved
/// `AR_CFG_LED`, `ath9k_hw_chip_reset` (COLD after FULL_SLEEP or with a
/// TX queue / RX still enabled, else WARM) and an `AR_SREV` that must
/// equal the probe's; the inactive preparation must equal the record's,
/// and calibration plus composition publish a fresh generation. A failed
/// reset leaves a fresh, un-calibrated owner; old station authorities
/// never reopen.
async fn reset(
    owner: &Mutex<Owner>,
    selected: Option<u16>,
    expected: Option<u32>,
) -> Result<ar9003::calib::Report, BringUpError> {
    let _control = CONTROL.lock().await;
    {
        let mut o = owner.lock().await;
        if o.removed || o.pinned || o.suspended {
            return Err(BringUpError::DeviceGone);
        }
        if expected.is_some_and(|generation| generation != o.generation) {
            return Err(BringUpError::BadState);
        }
        let target = selected.unwrap_or(o.primary);
        if selected.is_some() {
            let domain =
                narf_wireless::reg::db::ensure_domain().map_err(|_| BringUpError::Policy)?;
            calibration::Permission::from_domain_dual(&domain, target)?;
        }
        // An absent, unsigned or foreign record for the target never
        // retires the current generation.
        let grant = record(&o, target)?;
        if !retire(&mut o).await {
            return Err(BringUpError::BadState);
        }
        let command = identity::invoke(&o.cap, || narf_bus::pci::read_command(&o.cap, &o.device))
            .map_err(|_| BringUpError::DeviceGone)?
            .map_err(|_| BringUpError::DeviceGone)?;
        if command == u16::MAX || command & narf_bus::pci::cmd::BUS_MASTER != 0 {
            o.pinned = true;
            return Err(BringUpError::BadState);
        }
        // From here the old calibration/packet state is gone regardless of
        // outcome.
        o.radio = ar9003::calib::Calibration::default();
        o.attempted = true;
        let mut io = identity::Registers::new(o.mmio, o.cap);
        let wa = o.wa;
        // ath9k_hw_setpower(AWAKE) is a no-op unless FULL_SLEEP parked
        // the chip (its RTC SHUTDOWN then takes the power-on reset).
        if o.fullsleep {
            ar9003::set_power_awake(&mut io, wa)?;
        }
        let led = read_led(&mut io)?;
        let busy = io.read32(AR_Q_TXE);
        let cr = io.read32(AR_CR);
        if busy == u32::MAX || cr == u32::MAX {
            return Err(BringUpError::DeviceGone);
        }
        let cold = o.fullsleep || busy != 0 || cr & AR_CR_RXE_9300 != 0;
        // ath9k_hw_set_reset_reg; its ath9k_hw_setpower(AWAKE) is a no-op
        // (already awake) and `ar9003::phy::prepare` runs the
        // ath9k_hw_init_pll that follows.
        ar9003::reset_reg(&mut io, wa, cold)?;
        o.fullsleep = false;
        if ar9003::revision(&mut io, o.revision.chip)? != o.revision {
            return Err(BringUpError::BadIdentity);
        }
        let ctl = ctl_at(&o.identity, target)?;
        let identity = o.identity;
        let prepared = ar9003::phy::prepare(
            &mut io,
            &o.revision,
            &identity,
            o.pll_pwrsave,
            &o.image,
            target,
            ctl,
            0,
        )?;
        if prepared != prepared_at(&o, target)? {
            return Err(BringUpError::BadState);
        }
        o.led = led;
        o.prepared = prepared;
        o.primary = target;
        o.grant = grant;
        o.generation = o.generation.checked_add(1).ok_or(BringUpError::BadState)?;
        o.attempted = false;
    }
    initialize(owner).await
}

/// `main.c::ath_reset` on the current channel (`ath9k_queue_reset` ->
/// `ath_reset_work` -> `ath_reset_internal`, no fast channel change): the
/// station generation, its association, peer, host RSNA keys and netdev
/// stay; only the chip and its DMA engines restart.
///
/// `ath_prepare_reset` ([`station::Radio::pause_for_reset`]: interrupts
/// off, `ath_stoprecv`, `ath_drain_all_txq`, plus this tree's BME-off
/// quiescence proof), then `ath9k_hw_reset` for the same primary: the
/// pre-reset `AR_CFG_LED`, `ath9k_hw_chip_reset` (COLD while a TX queue or
/// RX is still enabled, else WARM), the probe's `AR_SREV`, the inactive
/// `ar9003::phy::prepare` that must equal the record's, the power plan at
/// this generation's host permission (`ath9k_hw_apply_txpower`), a fresh
/// `ar9003_hw_init_cal` (this tree keeps no per-channel `caldata`, so the
/// TX IQ/CL results are re-measured rather than restored), the station
/// MAC/queue program (`ar9003::mac::prepare`) and the AR9300 reset tail
/// (LED, NF load/start, BB watchdog). `ath_complete_reset`
/// ([`station::Radio::resume_after_reset`]) restarts RX/TX on the retained
/// rings and re-writes BSSID/AID and slot. Key cache: `ath9k_hw_reset`
/// never clears `AR_KEYTABLE` (only `ath9k_init_softc` resets it); this
/// owner uses no hardware key-cache entry (CCMP is host-side), so nothing
/// needs re-programming. Any failure closes the generation, which the
/// supervisor then retires through [`reset`].
async fn reset_in_place(owner: &Mutex<Owner>) -> Result<station::ResetType, BringUpError> {
    let _control = CONTROL.lock().await;
    let mut o = owner.lock().await;
    if o.removed || o.pinned || o.suspended {
        return Err(BringUpError::DeviceGone);
    }
    let station = o.station.clone().ok_or(BringUpError::BadState)?;
    let mut radio = station.lock().await;
    let kind = radio
        .pause_for_reset()
        .map_err(|_| BringUpError::BadState)?;
    let restarted = match hw_reset_in_place(&mut o, &mut radio).await {
        Ok(()) => radio
            .resume_after_reset()
            .map_err(|_| BringUpError::BadState),
        Err(error) => Err(error),
    };
    if let Err(error) = restarted {
        // The supervisor retires this closed generation next tick.
        let _ = radio.stop();
        return Err(error);
    }
    Ok(kind)
}

/// `hw.c::ath9k_hw_reset` (same channel) between the two halves of
/// [`reset_in_place`], on the paused station's retained native port.
async fn hw_reset_in_place(
    o: &mut Owner,
    radio: &mut super::NativeRadio,
) -> Result<(), BringUpError> {
    let native = radio.reset_port().ok_or(BringUpError::BadState)?;
    let command = identity::invoke(&o.cap, || narf_bus::pci::read_command(&o.cap, &o.device))
        .map_err(|_| BringUpError::DeviceGone)?
        .map_err(|_| BringUpError::DeviceGone)?;
    if command == u16::MAX || command & narf_bus::pci::cmd::BUS_MASTER != 0 {
        return Err(BringUpError::BadState);
    }
    let permission = native.ar9300_permission().ok_or(BringUpError::BadState)?;
    let mut io = identity::Registers::new(o.mmio, o.cap);
    let led = read_led(&mut io)?;
    let busy = io.read32(AR_Q_TXE);
    let cr = io.read32(AR_CR);
    if busy == u32::MAX || cr == u32::MAX {
        return Err(BringUpError::DeviceGone);
    }
    ar9003::reset_reg(&mut io, o.wa, busy != 0 || cr & AR_CR_RXE_9300 != 0)?;
    if ar9003::revision(&mut io, o.revision.chip)? != o.revision {
        return Err(BringUpError::BadIdentity);
    }
    let target = o.primary;
    let ctl = ctl_at(&o.identity, target)?;
    let identity = o.identity;
    let mut prepared = ar9003::phy::prepare(
        &mut io,
        &o.revision,
        &identity,
        o.pll_pwrsave,
        &o.image,
        target,
        ctl,
        0,
    )?;
    if prepared != prepared_at(o, target)? {
        return Err(BringUpError::BadState);
    }
    let grant = o.grant.clone();
    let plan = ar9003::power::plan(
        &o.image,
        target,
        ctl,
        permission.budget(),
        identity.tx_chainmask,
    )?;
    grant.invoke(|| ar9003::power::program(&mut io, &plan))?;
    prepared.power = plan;
    let revision = o.revision;
    let mut calibration = ar9003::calib::Calibration::default();
    // SAFETY: the chip was just reset and fully prepared for `prepared`
    // (power re-programmed); `pause_for_reset` proved every RX/TX engine
    // idle with bus mastering off (re-read above), so no packet DMA runs
    // while the calibration owns the baseband. CONTROL and the owner and
    // station locks serialize the attempt.
    let report = unsafe {
        calibrate(
            &mut calibration,
            &mut io,
            &identity,
            &revision,
            &prepared,
            &grant,
            permission,
        )
    }
    .await?;
    let failed = |_| BringUpError::BadState;
    ar9003::mac::prepare(
        native,
        &identity,
        &o.image[..],
        identity.mac,
        report.five_ghz,
    )
    .map_err(failed)?;
    let periodic = ar9003::calib::Periodic::new(
        &revision,
        &report,
        *o.totals.lock(),
        narf_time::monotonic_ns() / 1_000_000,
    );
    native
        .ar9300_recalibrated(report, periodic)
        .map_err(failed)?;
    native.ar9300_reset_tail(led).map_err(failed)?;
    o.led = led;
    o.prepared = prepared;
    o.radio = calibration;
    Ok(())
}

/// Rejoin supervisor and `link.c::ath_ani_calibrate` cadence. A terminal
/// station generation (disassociation, link loss, fatal interrupt, BB
/// watchdog or failed DMA) is followed by a generation reset into a fresh
/// passive station; a pinned or removed owner is never followed. Every
/// tick the live station runs the due `ar9003_hw_calibrate` steps through
/// `ar9003::calib::Periodic` (IQ per-calibration while not `caldone`, the
/// 20 min `ath9k_hw_reset_calvalid` restart, the `ATH_LONG_CALINTERVAL` NF
/// history/load/restart). A failed calibration closes the generation,
/// which is then reset.
async fn supervise(owner: Shared) {
    let mut failures = 0u32;
    loop {
        narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(SUPERVISE_NS)).await;
        let station = {
            let o = owner.lock().await;
            if o.removed || o.pinned {
                return;
            }
            if o.suspended {
                continue;
            }
            match o.station.clone() {
                Some(station) => station,
                None => continue,
            }
        };
        let mut queued = None;
        let terminal = {
            let Some(mut radio) = station.try_lock() else {
                continue;
            };
            if radio.terminal() {
                true
            } else {
                // `ath_hw_check_work`: a queued `ath9k_queue_reset` cause
                // (FATAL, BB watchdog, TX hang, calibration) or RX
                // inactivity is recovered by the in-place `ath_reset`.
                queued = radio
                    .reset_pending()
                    .or_else(|| radio.rx_inactive_check(narf_time::monotonic_ns() / 1_000_000));
                if queued.is_some() {
                    false
                } else {
                    match radio.long_calibration() {
                        Ok(_) | Err(station::Error::Transport(packet::Error::Busy)) => {}
                        Err(error) => {
                            // A queued RESET_TYPE_CALIBRATION is reset in place
                            // next tick; anything else closed the generation.
                            let _ = writeln!(
                                narf_console::Writer,
                                "ath9k: AR9003 periodic calibration failed: {:?}",
                                error
                            );
                        }
                    }
                    false
                }
            }
        };
        if let Some(kind) = queued {
            drop(station);
            match reset_in_place(&owner).await {
                Ok(_) => {
                    let _ = writeln!(
                        narf_console::Writer,
                        "ath9k: AR9003 in-place reset ({:?}) restarted RX/TX; association kept",
                        kind
                    );
                }
                Err(error) => {
                    // The closed generation is retired on the next tick.
                    let _ = writeln!(
                        narf_console::Writer,
                        "ath9k: AR9003 in-place reset ({:?}) closed: {:?}",
                        kind,
                        error
                    );
                }
            }
            continue;
        }
        if !terminal {
            continue;
        }
        drop(station);
        match reset(&owner, None, None).await {
            Ok(_) => {
                failures = 0;
                let generation = owner.lock().await.generation;
                let _ = writeln!(
                    narf_console::Writer,
                    "ath9k: AR9003 station generation {} published after reset",
                    generation
                );
            }
            Err(error) => {
                failures += 1;
                let _ = writeln!(
                    narf_console::Writer,
                    "ath9k: AR9003 generation reset closed: {:?}",
                    error
                );
                // Bounded retries; a pinned or removed owner never resets.
                if failures >= 3
                    || matches!(error, BringUpError::DeviceGone | BringUpError::BadState)
                {
                    return;
                }
            }
        }
    }
}

/// `ath_pci_remove`: withdraw, stop and reclaim DMA, then release the
/// singleton address; an unproven stop keeps it reserved.
pub(super) fn remove(device: BusDevice, _cap: Cap<BusDeviceCap, Write>) {
    let Some(owner) = OWNER.lock().clone() else {
        return;
    };
    narf_scheduler::spawn(async move {
        let _control = CONTROL.lock().await;
        let mut o = owner.lock().await;
        if o.device.addr != device.addr {
            return;
        }
        o.removed = true;
        let reclaimed = retire(&mut o).await;
        // ieee80211_unregister_hw: the netdev leaves with the device.
        interface::unpublish();
        if reclaimed {
            // `ath9k_stop` parks the PCIe SerDes in its awake array
            // (`ath9k_hw_configpcipowersave(ah, true)`); best effort
            // on a device that is already going away.
            let mut io = identity::Registers::new(o.mmio, o.cap);
            let tables = ar9003::ini::Tables::for_revision(&o.revision, &o.identity, o.pll_pwrsave);
            let _ =
                ar9003::serdes::configure(&mut io, &o.revision, &tables, true, o.wa, o.aspm_l1_fix);
        }
        drop(o);
        let mut retained = OWNER.lock();
        if retained.as_ref().is_some_and(|r| Arc::ptr_eq(r, &owner)) {
            *retained = None;
            *WOWLAN_SUPPORT.lock() = None;
            *WOWLAN.lock() = None;
        }
        drop(retained);
        if reclaimed {
            let mut claimed = CLAIMED_ADDRESS.lock();
            if *claimed == Some(device.addr) {
                *claimed = None;
            }
        }
        let _ = writeln!(
            narf_console::Writer,
            "ath9k: AR9003 removed; DMA {}",
            if reclaimed {
                "reclaimed"
            } else {
                "pinned, address quarantined"
            }
        );
    });
}

async fn retire(o: &mut Owner) -> bool {
    let Some(station) = o.station.take() else {
        return !o.pinned;
    };
    interface::retire(&station);
    let reclaimed = station.lock().await.retire();
    if !reclaimed {
        o.pinned = true;
    }
    reclaimed
}

/// `pci.c::ath_pci_suspend`: retire the station and its DMA, then
/// `ath9k_hw_disable` (AWAKE, COLD `ath9k_hw_set_reset_reg`,
/// `ath9k_hw_init_pll`) and `ath9k_hw_setpower(FULL_SLEEP)`
/// (`ar9003::disable_and_sleep`). A generation reset in flight holds
/// `CONTROL` and reports Busy.
pub(super) fn pm_suspend() -> Result<(), narf_power::device_pm::DeviceSuspendError> {
    use narf_power::device_pm::DeviceSuspendError;
    let _control = CONTROL.try_lock().ok_or(DeviceSuspendError::Busy)?;
    let Some(owner) = OWNER.lock().clone() else {
        return Ok(());
    };
    let mut o = owner.try_lock().ok_or(DeviceSuspendError::Busy)?;
    if o.removed {
        return Ok(());
    }
    if o.pinned {
        return Err(DeviceSuspendError::DriverError);
    }
    // mac80211 `ieee80211_suspend` -> `ath9k_suspend` with a WoWLAN
    // configuration, then `ath_pci_suspend` bypassed ("WOW is enabled").
    // Linux's `ret = 1` (no association, no trigger) and a failed arming
    // fall back to the ordinary suspend below.
    if wow_suspend(&mut o)? {
        return Ok(());
    }
    if let Some(station) = o.station.clone() {
        let mut radio = station.try_lock().ok_or(DeviceSuspendError::Busy)?;
        interface::retire(&station);
        if !radio.retire() {
            o.pinned = true;
            return Err(DeviceSuspendError::DriverError);
        }
    }
    o.station = None;
    // No later initialization reuses this calibration or generation; only
    // resume's generation reset re-proves the chip.
    o.radio = ar9003::calib::Calibration::default();
    o.attempted = true;
    o.suspended = true;
    o.fullsleep = true;
    let mut io = identity::Registers::new(o.mmio, o.cap);
    ar9003::disable_and_sleep(&mut io, o.wa).map_err(|_| DeviceSuspendError::DriverError)
}

/// `wow.c::ath9k_suspend` for an armed WoW configuration on an associated
/// station: the disassociate/deauthenticate patterns (slots 0/1), the
/// user patterns (slots 2..), the interrupt switch to BMISS
/// ([`station::Radio::wow_suspend`]) and `ar9003_wow.c::ath9k_hw_wow_enable`
/// with the keep-alive null frame (`ah->txchainmask`, current band, own
/// MAC, AP). ANI/calibration and the hang check stop with the supervisor
/// (`suspended`). `Ok(false)`: WoW does not apply (Linux `ret = 1`) or
/// arming failed; the caller then takes the ordinary suspend, which retires
/// the station. MCI/btcoex is not involved (`mci_enabled` false).
fn wow_suspend(o: &mut Owner) -> Result<bool, narf_power::device_pm::DeviceSuspendError> {
    use narf_power::device_pm::DeviceSuspendError;
    let (Some(mut wow), Some(config)) = (o.wow, WOWLAN.lock().clone()) else {
        return Ok(false);
    };
    let Some(station) = o.station.clone() else {
        return Ok(false);
    };
    let mut radio = station.try_lock().ok_or(DeviceSuspendError::Busy)?;
    let triggers = ar9003::wow::map_triggers(&ar9003::wow::WowlanRequest {
        disconnect: config.disconnect,
        magic_pkt: config.magic_packet,
        n_patterns: config.patterns.len() as u8,
    });
    let Some(bssid) = radio.wow_admissible() else {
        return Ok(false);
    };
    if triggers == 0 {
        return Ok(false);
    }
    let mut io = identity::Registers::new(o.mmio, o.cap);
    let armed = (|| {
        for (slot, pattern) in ar9003::wow::disassoc_deauth_patterns(&bssid)
            .iter()
            .enumerate()
        {
            wow.apply_pattern(&mut io, &pattern.bytes, &pattern.mask, slot, pattern.len)?;
        }
        if triggers & ar9003::wow::AH_WOW_USER_PATTERN_EN != 0 {
            // ath9k_wow_add_pattern: zero-padded pattern, the cfg80211
            // bitmask bytes copied as is, slot i + 2.
            for (index, user) in config.patterns.iter().enumerate() {
                let mut bytes = [0; ar9003::wow::MAX_PATTERN_SIZE];
                let mut mask = [0; ar9003::wow::MAX_PATTERN_MASK_SIZE];
                let len = user.pattern.len();
                bytes
                    .get_mut(..len)
                    .ok_or(BringUpError::BadState)?
                    .copy_from_slice(&user.pattern);
                mask.get_mut(..user.mask.len())
                    .ok_or(BringUpError::BadState)?
                    .copy_from_slice(&user.mask);
                let len = u8::try_from(len).map_err(|_| BringUpError::BadState)?;
                wow.apply_pattern(&mut io, &bytes, &mask, index + 2, len)?;
            }
        }
        radio.wow_suspend().map_err(|_| BringUpError::BadState)?;
        wow.enable(
            &mut io,
            &o.revision,
            triggers,
            &ar9003::wow::KeepAlive {
                tx_chainmask: o.identity.tx_chainmask,
                is_2ghz: o.primary < 4800,
                sta_mac: o.identity.mac,
                ap_mac: bssid,
            },
        )
    })();
    if let Err(error) = armed {
        let _ = writeln!(
            narf_console::Writer,
            "ath9k: AR9462 WoW arming failed ({:?}); ordinary suspend",
            error
        );
        return Ok(false);
    }
    drop(radio);
    o.wow = Some(wow);
    o.wow_sleeping = true;
    o.suspended = true;
    let _ = writeln!(
        narf_console::Writer,
        "ath9k: AR9462 suspend with WoW triggers {:#x}; association kept",
        triggers
    );
    Ok(true)
}

/// `wow.c::ath9k_resume`: the saved interrupt mask
/// ([`station::Radio::wow_resume`], which also queues the RX-inactivity
/// in-place reset that restarts the RX DMA `ath9k_hw_wow_enable` stopped),
/// then `ath9k_hw_wow_wakeup` (wake reason, PME clear, event clear,
/// `INIT_RSSI_THR`) and its `ath9k_hw_configpcipowersave(ah, false)`
/// (`ar9003::serdes::configure`). TSF2 has no generic-timer owner here, so
/// `tsf2_restart` is only reported. The supervisor then runs
/// `ath_restart_work`'s hang check, i.e. the in-place reset, keeping the
/// station generation and its association. A failed interrupt restore
/// closes the generation; the supervisor retires it.
fn wow_resume(o: &mut Owner) -> Result<(), narf_power::device_pm::DeviceSuspendError> {
    use narf_power::device_pm::DeviceSuspendError;
    let station = o.station.clone();
    o.wow_sleeping = false;
    o.suspended = false;
    if let Some(station) = station {
        let mut radio = station.try_lock().ok_or(DeviceSuspendError::Busy)?;
        if let Err(error) = radio.wow_resume() {
            let _ = writeln!(
                narf_console::Writer,
                "ath9k: AR9462 WoW interrupt restore closed the station: {:?}",
                error
            );
        }
    }
    let mut io = identity::Registers::new(o.mmio, o.cap);
    let revision = o.revision;
    let mut wow = o.wow.ok_or(DeviceSuspendError::DriverError)?;
    let wakeup = wow
        .wakeup(&mut io, &revision)
        .map_err(|_| DeviceSuspendError::DriverError)?;
    o.wow = Some(wow);
    if wakeup.restore_pcie_powersave {
        let tables = ar9003::ini::Tables::for_revision(&revision, &o.identity, o.pll_pwrsave);
        ar9003::serdes::configure(&mut io, &revision, &tables, false, o.wa, o.aspm_l1_fix)
            .map_err(|_| DeviceSuspendError::DriverError)?;
    }
    let _ = writeln!(
        narf_console::Writer,
        "ath9k: AR9462 resume with WoW status {:#x}",
        wakeup.status
    );
    Ok(())
}

/// `pci.c::ath_pci_resume`: re-disable PCI RETRY_TIMEOUT (config 0x41) that
/// suspend reset, then a generation reset (COLD after FULL_SLEEP, identical
/// `AR_SREV`, INI/PLL/RF and board values, AR9300 TX power, calibration)
/// republishes the station at the retained primary.
pub(super) fn pm_resume() -> Result<(), narf_power::device_pm::DeviceSuspendError> {
    use narf_power::device_pm::DeviceSuspendError;
    let Some(owner) = OWNER.lock().clone() else {
        return Ok(());
    };
    {
        let mut o = owner.try_lock().ok_or(DeviceSuspendError::Busy)?;
        if !o.suspended || o.removed {
            return Ok(());
        }
        let (cap, device) = (o.cap, o.device);
        let value = identity::invoke(&cap, || narf_bus::pci::read_config32(&cap, &device, 0x40))
            .map_err(|_| DeviceSuspendError::DriverError)?
            .map_err(|_| DeviceSuspendError::DriverError)?;
        if value & 0xff00 != 0 {
            identity::invoke(&cap, || {
                narf_bus::pci::write_config32(&cap, &device, 0x40, value & 0xffff_00ff)
            })
            .map_err(|_| DeviceSuspendError::DriverError)?
            .map_err(|_| DeviceSuspendError::DriverError)?;
        }
        // `ath_pci_resume` runs for a WoW resume too; `ath9k_resume` then
        // keeps the generation instead of the reset below.
        if o.wow_sleeping {
            return wow_resume(&mut o);
        }
        o.suspended = false;
    }
    narf_scheduler::spawn(async move {
        if let Err(error) = reset(&owner, None, None).await {
            let _ = writeln!(
                narf_console::Writer,
                "ath9k: AR9003 resume reset closed: {:?}",
                error
            );
        }
    });
    Ok(())
}
