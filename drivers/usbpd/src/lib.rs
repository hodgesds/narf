//! TCPC drivers — implementations of `narf_usbpd::tcpc::Tcpc`.
//!
//! Each chip is its own module. Driver code is clean-room from the
//! vendor's public silicon datasheet; no GPL/BSD source consulted.
//! See `specification/spec.md` for the per-chip reference list.
//!
//! ## Surface
//!
//! - [`fusb302`] — ON Semiconductor FUSB302B (low-level BMC PHY).
//! - [`tps65987`] — TI TPS65987DDH (firmware-driven PD controller).
//! - [`i2c_bridge`] — sync façade that wraps `narf_drivers_i2c::I2cBus`
//!   so the chip drivers' sync `I2cBus` trait can ride the kernel's
//!   async I²C controllers.
//! - [`register_initcalls`] — Stage::Late initcall: walks every
//!   registered I²C bus, probes each for a TCPC chip, and parks any
//!   detected chip in [`PORTS`] for the (future) TCPM step task.
//!
//! References (public, non-GPL only):
//! - **USB Power Delivery 3.1 v1.8** (USB-IF).
//!   <https://www.usb.org/document-library/usb-power-delivery>
//! - **USB Type-C Cable and Connector Specification 2.2** (USB-IF).
//!   <https://www.usb.org/document-library/usb-type-c-cable-and-connector-specification-revision-22>
//! - **USB Type-C Port Controller Interface Specification 2.0**
//!   (USB-IF, TCPCI 2.0).
//!   <https://www.usb.org/document-library/usb-type-c-port-controller-interface-specification-revision-20>

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

pub mod altmode_dp;
pub mod dp_gpu_bridge;
pub mod fusb302;
pub mod i2c_bridge;
pub mod policy;
pub mod tcpm;
pub mod tps65987;
pub mod ucsi;
mod ucsi_acpi;

mod tests;

use alloc::sync::Arc;
use alloc::vec::Vec;
use narf_lib::sync::IrqSafeSpinLock;
use narf_usbpd::tcpc::Tcpc;

/// One bound TCPC port — the chip handle plus identifying metadata
/// for diagnostics. Stored in the global [`PORTS`] registry.
#[derive(Debug)]
pub struct PortBinding {
    /// Stable name from the host I²C controller (typically the ACPI
    /// path of the controller, e.g. `\_SB.I2CA`).
    pub bus_name: alloc::string::String,
    /// 7-bit I²C target address the chip responds at.
    pub i2c_addr: u8,
    /// Chip-side TCPC handle. The TCPM step task drives this once
    /// it lands.
    pub tcpc: Arc<dyn Tcpc>,
}

/// Global registry of detected TCPC ports. Populated by
/// [`register_initcalls`]; consumed by the (future) TCPM step task.
pub static PORTS: IrqSafeSpinLock<Vec<PortBinding>> = IrqSafeSpinLock::new(Vec::new());

/// Stage::Late initcall: walk every registered I²C bus, probe known
/// TCPC chips at their datasheet I²C addresses, and park any
/// successful detection in [`PORTS`]. Quiet on systems with no
/// matching chip (typical for QEMU without TCPC emulation).
///
/// Probe order:
/// 1. **FUSB302B** at the default 7-bit address `0x22` (datasheet
///    "Pin Description / I²C Address"). DEVICE_ID high-nibble must
///    be ≥ 0x8 to match a real FUSB302 silicon revision.
/// 2. **TPS65987DDH** at `0x38` (TPS65987 TRM §"Host Interface").
///    Vendor-ID register must read `0x0451` (TI's USB-IF VID).
pub fn register_initcalls() {
    use core::fmt::Write as _;
    use narf_init::{InitResult, Stage};
    narf_init::register(Stage::Late, "usbpd-ucsi-acpi", ucsi_acpi::probe);
    narf_init::register(Stage::Late, "usbpd-tcpc-probe", || {
        // A firmware PPM owns the PD controller. Raw I2C probing and a
        // second policy engine must not compete with it, even if _DSM fails.
        if !narf_aml::find_all_devices_by_hid("PNP0CA0").is_empty() {
            return InitResult::NotPresent;
        }
        let buses = narf_drivers_i2c::registered_buses();
        if buses.is_empty() {
            let _ = writeln!(
                narf_console::Writer,
                "  tcpm: no PD chips detected (no I²C buses registered)"
            );
            return InitResult::NotPresent;
        }
        let mut detected = 0usize;
        for bus in &buses {
            detected += probe_bus(bus);
        }
        if detected == 0 {
            let _ = writeln!(narf_console::Writer, "  tcpm: no PD chips detected");
            InitResult::NotPresent
        } else {
            InitResult::Ok
        }
    });
}

/// Probe one I²C bus for every supported TCPC chip. Returns the
/// number of chips registered.
fn probe_bus(bus: &Arc<dyn narf_drivers_i2c::I2cBus>) -> usize {
    use core::fmt::Write as _;
    let mut n = 0usize;
    let bus_name = bus.name();
    let bridge = Arc::new(i2c_bridge::KernelBusBridge::new(bus.clone()));

    // FUSB302B at 0x22.
    let fusb = fusb302::Fusb302::new(bridge.clone(), fusb302::FUSB302_DEFAULT_I2C_ADDR);
    if let Ok(id) = fusb.probe_device_id() {
        // Init brings up the BMC PHY; failure here means the chip is
        // present but reset cleared something the datasheet says we
        // need to re-program. Surface as "detected" anyway so a
        // future debug pass can pick it up.
        let _ = fusb.init();
        let _ = writeln!(
            narf_console::Writer,
            "  usbpd: FUSB302 detected on bus '{}' addr 0x22 device_id=0x{:02x}",
            bus_name,
            id
        );
        let chip: Arc<dyn Tcpc> = Arc::new(fusb);
        register_port(bus_name, fusb302::FUSB302_DEFAULT_I2C_ADDR, chip);
        n += 1;
    }

    // TPS65987DDH at 0x38.
    let tps = tps65987::Tps65987::new(bridge, tps65987::TPS65987_DEFAULT_I2C_ADDR);
    if let Ok((vendor, device)) = tps.probe() {
        let _ = writeln!(
            narf_console::Writer,
            "  usbpd: TPS65987 detected on bus '{}' addr 0x38 vid=0x{:04x} did=0x{:04x}",
            bus_name,
            vendor,
            device
        );
        let chip: Arc<dyn Tcpc> = Arc::new(tps);
        register_port(bus_name, tps65987::TPS65987_DEFAULT_I2C_ADDR, chip);
        n += 1;
    }

    n
}

/// Park a detected TCPC in [`PORTS`], spawn the per-port TCPM task
/// (drives both sink and source state machines based on CC
/// orientation), and spawn a DP Alt Mode discovery task that wakes
/// once the TCPM reaches Ready.
fn register_port(bus_name: &str, i2c_addr: u8, tcpc: Arc<dyn Tcpc>) {
    let label = alloc::format!("{}@0x{:02x}", bus_name, i2c_addr);
    // Connector id is the registry index — every USB-C receptacle
    // owns a small stable integer for DP Alt → GPU bridge lookup.
    let connector_idx = PORTS.lock().len() as u32;
    PORTS.lock().push(PortBinding {
        bus_name: bus_name.into(),
        i2c_addr,
        tcpc: tcpc.clone(),
    });
    let port = Arc::new(tcpm::TcpmPort::new(
        tcpc,
        policy::SinkPolicy::default(),
        policy::SourcePolicy::default(),
        label.clone(),
    ));
    tcpm::register_port(port.clone());
    // #1211: one TypecConnector per TCPC binding, published through BOTH
    // registries at creation — the single publication path. UCSI
    // connectors take the same path (ucsi::publish). A connector is owned
    // by exactly one producer (extcon spec §4: host PD/mux operations must
    // not compete with firmware for one connector); on this platform the
    // two producers are mutually exclusive anyway, since PNP0CA0 presence
    // makes register_initcalls skip TCPC probing entirely.
    let typec = publish_tcpc_connector(&label);
    let alt = Arc::new(altmode_dp::DpAltModePort::new(
        port.clone(),
        dp_gpu_bridge::ConnectorId::from_index(connector_idx),
        typec.clone(),
    ));
    altmode_dp::register_port(alt.clone());
    spawn_tcpm_task(port, label.clone(), typec);
    altmode_dp::spawn_discovery_task(alt, label);
}

/// Create and register one TypecConnector for a TCPC binding, through BOTH
/// the extcon registry and `TYPEC_REGISTRY`.
///
/// This is the single publication path: every producer registers through
/// both registries at creation, exactly once per connector object.
/// `TYPEC_REGISTRY` has no dedup and the sysfs bridge publishes one
/// `port<N>` per entry, so a second registration of the same object
/// would double-publish it.
///
/// Testable seam: exercises publication without spawning tasks.
pub(crate) fn publish_tcpc_connector(
    label: &str,
) -> Arc<narf_drivers_extcon::typec::TypecConnector> {
    // Connector names are boot-lifetime objects.
    let name = alloc::boxed::Box::leak(alloc::format!("typec-{}", label).into_boxed_str());
    let conn = Arc::new(narf_drivers_extcon::typec::TypecConnector::new(name));
    narf_drivers_extcon::class::register(conn.clone());
    narf_drivers_extcon::typec_class::typec_register(conn.clone());
    conn
}

/// Mirror live TCPM state into a TCPC-owned TypecConnector. Called by the
/// TCPM task on every port-state change and on data-role-swap outcomes
/// (a power-role swap always changes `PortState`, so the state-change
/// call already covers it).
///
/// Roles come from the attach side. The data role defaults by side
/// (source → host, sink → device) and is corrected by DR-swap outcomes;
/// sink-side DR swap does not exist yet (G7). Detach and error recovery
/// clear roles and entered alt modes; BIST leaves class state untouched.
/// Orientation comes from the live CC snapshot; a failed CC read leaves
/// the previous orientation in place rather than inventing one.
pub(crate) fn sync_typec_connector(
    conn: &Arc<narf_drivers_extcon::typec::TypecConnector>,
    port: &tcpm::TcpmPort,
) {
    use narf_drivers_extcon::typec::{DataRole, PowerRole};
    match port.state() {
        tcpm::PortState::Unattached | tcpm::PortState::ErrorRecovery => {
            conn.set_power_role(PowerRole::Dual);
            conn.set_data_role(DataRole::Dual);
            for mode in conn.entered_alt_modes() {
                conn.set_alt_mode(mode, false);
            }
            if let Ok(cc) = port.tcpc().cc_status() {
                conn.update_cc(cc);
            }
        }
        tcpm::PortState::AttachedSnk => {
            conn.set_power_role(PowerRole::Sink);
            conn.set_data_role(DataRole::Device);
            if let Ok(cc) = port.tcpc().cc_status() {
                conn.update_cc(cc);
            }
        }
        tcpm::PortState::AttachedSrc => {
            conn.set_power_role(PowerRole::Source);
            conn.set_data_role(if port.source().is_dfp() {
                DataRole::Host
            } else {
                DataRole::Device
            });
            if let Ok(cc) = port.tcpc().cc_status() {
                conn.update_cc(cc);
            }
        }
        tcpm::PortState::Bist => {}
    }
}

/// Spawn an async task that drives one TCPM port to a Ready contract
/// (sink *or* source, picked from CC at attach time) and keeps it
/// alive across detach + re-attach. Cadence derived from USB-PD 3.1
/// §8.3 + §6.6.1: short between Advanced steps (yield only), 25 ms
/// while Idle, 100 ms once Ready.
///
/// Sleeps are calibrated wall-clock via `narf_time::Deadline`. The
/// previous incarnation used `sleep_cycles(330_000_000)` etc. which
/// assumed a ~3.3 GHz TSC — on Renoir 4700U (2.0 GHz) that came out as
/// 165 ms and on Phoenix HawkPoint1 (4.6 GHz) as 72 ms, so the cadence
/// drifted by >2x across our two bring-up targets. Same bug class as
/// the LAPIC initial_count note: hard-coded cycle counts read as
/// timing bugs on real silicon.
fn spawn_tcpm_task(
    port: Arc<tcpm::TcpmPort>,
    label: alloc::string::String,
    typec: Arc<narf_drivers_extcon::typec::TypecConnector>,
) {
    use core::fmt::Write as _;
    use narf_time::{Deadline, SleepUntil};
    use tcpm::{PortState, PortStepOutcome};
    narf_scheduler::spawn(async move {
        let cap = narf_usbpd::bootstrap_usbpd_authority();
        let mut last_logged_state = PortState::Unattached;
        let mut announced = false;
        loop {
            let outcome = match port.step(&cap) {
                Ok(o) => o,
                Err(e) => {
                    let _ = writeln!(
                        narf_console::Writer,
                        "  tcpm: {} step failed: {:?}",
                        label,
                        e
                    );
                    if matches!(e, tcpm::SourceError::AuthorityRevoked) {
                        return;
                    }
                    SleepUntil::new(Deadline::after_ms(100).as_instant()).await;
                    continue;
                }
            };
            if port.state() != last_logged_state {
                last_logged_state = port.state();
                // #1211: mirror the new attach/role state into the class.
                sync_typec_connector(&typec, &port);
                let _ = writeln!(
                    narf_console::Writer,
                    "  tcpm: {} → {:?}",
                    label,
                    last_logged_state
                );
                if !matches!(
                    last_logged_state,
                    PortState::AttachedSnk | PortState::AttachedSrc
                ) {
                    announced = false;
                }
            }
            match outcome {
                PortStepOutcome::SinkReady(c) | PortStepOutcome::SourceReady(c) => {
                    if !announced {
                        let _ = writeln!(
                            narf_console::Writer,
                            "  tcpm: {} contract: PDO#{} {} mV @ {} mA",
                            label,
                            c.object_position,
                            c.voltage_mv,
                            c.op_current_ma
                        );
                        announced = true;
                    }
                    SleepUntil::new(Deadline::after_ms(100).as_instant()).await;
                }
                PortStepOutcome::Idle(_) => {
                    SleepUntil::new(Deadline::after_ms(25).as_instant()).await;
                }
                PortStepOutcome::Advanced(_) => {
                    narf_scheduler::yield_now().await;
                }
                PortStepOutcome::BistEntered => {
                    let _ = writeln!(narf_console::Writer, "  tcpm: {} entered BIST", label);
                    SleepUntil::new(Deadline::after_ms(100).as_instant()).await;
                }
                PortStepOutcome::RoleSwapped(next) => {
                    let _ = writeln!(
                        narf_console::Writer,
                        "  tcpm: {} power role swapped → {:?}",
                        label,
                        next
                    );
                    announced = false;
                    narf_scheduler::yield_now().await;
                }
                PortStepOutcome::DataRoleSwapped { now_dfp } => {
                    let _ = writeln!(
                        narf_console::Writer,
                        "  tcpm: {} data role swapped → {}",
                        label,
                        if now_dfp { "DFP" } else { "UFP" }
                    );
                    // PortState does not change on a DR swap, so the
                    // state-change branch above does not fire: sync here.
                    sync_typec_connector(&typec, &port);
                    narf_scheduler::yield_now().await;
                }
                PortStepOutcome::VconnSwapped { now_supplying } => {
                    let _ = writeln!(
                        narf_console::Writer,
                        "  tcpm: {} VConn swapped → {}",
                        label,
                        if now_supplying {
                            "supplier"
                        } else {
                            "consumer"
                        }
                    );
                    narf_scheduler::yield_now().await;
                }
                PortStepOutcome::EprModeEntered => {
                    let _ = writeln!(narf_console::Writer, "  tcpm: {} entered EPR mode", label);
                    narf_scheduler::yield_now().await;
                }
            }
        }
    });
}

/// Number of TCPC ports currently bound. Useful for tests +
/// diagnostics.
pub fn bound_port_count() -> usize {
    PORTS.lock().len()
}
